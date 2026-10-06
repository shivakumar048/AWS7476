"""Windows enforcement layer (ctypes, no third-party packages).

* WH_KEYBOARD_LL hook  -> blocks Ctrl+C / Ctrl+V / Ctrl+X / Delete / ... system-wide
* WH_MOUSE_LL hook     -> pins the cursor while a button is held, so no drag & drop can start
* Clipboard listener   -> wipes the clipboard whenever something is copied by any means
                          (right-click menus, Edit menu, programmatic copies)

Hooks must run in the interactive user's session, so start this at logon
(see install/install-task.ps1), not as a Windows service.
"""

from __future__ import annotations

import ctypes
import sys
import threading
import time
from ctypes import wintypes as wt
from typing import Callable

from .rules import ALT, CTRL, SHIFT, WIN, Guard

if sys.platform != "win32":  # pragma: no cover - imported only on Windows
    raise ImportError("guard.win32 requires Windows")

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

LRESULT = ctypes.c_ssize_t
HOOKPROC = ctypes.WINFUNCTYPE(LRESULT, ctypes.c_int, wt.WPARAM, wt.LPARAM)
WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM)

WH_KEYBOARD_LL, WH_MOUSE_LL = 13, 14
HC_ACTION = 0
WM_KEYDOWN, WM_KEYUP, WM_SYSKEYDOWN, WM_SYSKEYUP = 0x100, 0x101, 0x104, 0x105
WM_MOUSEMOVE, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_RBUTTONDOWN, WM_RBUTTONUP = 0x200, 0x201, 0x202, 0x204, 0x205
WM_CLIPBOARDUPDATE = 0x031D
WM_QUIT = 0x0012
HWND_MESSAGE = wt.HWND(-3)
GA_ROOT = 2
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
VK_SHIFT, VK_CONTROL, VK_MENU, VK_LWIN, VK_RWIN = 0x10, 0x11, 0x12, 0x5B, 0x5C


class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [("vkCode", wt.DWORD), ("scanCode", wt.DWORD), ("flags", wt.DWORD),
                ("time", wt.DWORD), ("dwExtraInfo", ctypes.c_size_t)]


class MSLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [("pt", wt.POINT), ("mouseData", wt.DWORD), ("flags", wt.DWORD),
                ("time", wt.DWORD), ("dwExtraInfo", ctypes.c_size_t)]


class WNDCLASSW(ctypes.Structure):
    _fields_ = [("style", wt.UINT), ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int), ("hInstance", wt.HINSTANCE), ("hIcon", wt.HICON),
                ("hCursor", wt.HANDLE), ("hbrBackground", wt.HBRUSH),
                ("lpszMenuName", wt.LPCWSTR), ("lpszClassName", wt.LPCWSTR)]


def _sig(fn, argtypes, restype):
    fn.argtypes, fn.restype = argtypes, restype


_sig(user32.SetWindowsHookExW, [ctypes.c_int, HOOKPROC, wt.HINSTANCE, wt.DWORD], wt.HHOOK)
_sig(user32.CallNextHookEx, [wt.HHOOK, ctypes.c_int, wt.WPARAM, wt.LPARAM], LRESULT)
_sig(user32.UnhookWindowsHookEx, [wt.HHOOK], wt.BOOL)
_sig(user32.GetMessageW, [ctypes.POINTER(wt.MSG), wt.HWND, wt.UINT, wt.UINT], wt.BOOL)
_sig(user32.TranslateMessage, [ctypes.POINTER(wt.MSG)], wt.BOOL)
_sig(user32.DispatchMessageW, [ctypes.POINTER(wt.MSG)], LRESULT)
_sig(user32.PostThreadMessageW, [wt.DWORD, wt.UINT, wt.WPARAM, wt.LPARAM], wt.BOOL)
_sig(user32.GetAsyncKeyState, [ctypes.c_int], wt.SHORT)
_sig(user32.GetForegroundWindow, [], wt.HWND)
_sig(user32.WindowFromPoint, [wt.POINT], wt.HWND)
_sig(user32.GetAncestor, [wt.HWND, wt.UINT], wt.HWND)
_sig(user32.GetWindowThreadProcessId, [wt.HWND, ctypes.POINTER(wt.DWORD)], wt.DWORD)
_sig(user32.RegisterClassW, [ctypes.POINTER(WNDCLASSW)], wt.ATOM)
_sig(user32.CreateWindowExW, [wt.DWORD, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD, ctypes.c_int, ctypes.c_int,
                              ctypes.c_int, ctypes.c_int, wt.HWND, wt.HMENU, wt.HINSTANCE, wt.LPVOID], wt.HWND)
_sig(user32.DestroyWindow, [wt.HWND], wt.BOOL)
_sig(user32.DefWindowProcW, [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM], LRESULT)
_sig(user32.AddClipboardFormatListener, [wt.HWND], wt.BOOL)
_sig(user32.RemoveClipboardFormatListener, [wt.HWND], wt.BOOL)
_sig(user32.OpenClipboard, [wt.HWND], wt.BOOL)
_sig(user32.EmptyClipboard, [], wt.BOOL)
_sig(user32.CloseClipboard, [], wt.BOOL)
_sig(user32.CountClipboardFormats, [], ctypes.c_int)
_sig(user32.GetClipboardOwner, [], wt.HWND)
_sig(kernel32.GetModuleHandleW, [wt.LPCWSTR], wt.HMODULE)
_sig(kernel32.GetCurrentThreadId, [], wt.DWORD)
_sig(kernel32.OpenProcess, [wt.DWORD, wt.BOOL, wt.DWORD], wt.HANDLE)
_sig(kernel32.QueryFullProcessImageNameW, [wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)], wt.BOOL)
_sig(kernel32.CloseHandle, [wt.HANDLE], wt.BOOL)


def process_of_window(hwnd) -> str | None:
    if not hwnd:
        return None
    pid = wt.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value)
    if not handle:
        return None
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = wt.DWORD(len(buf))
        if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return buf.value
        return None
    finally:
        kernel32.CloseHandle(handle)


def _pressed_modifiers() -> frozenset[str]:
    down = lambda vk: bool(user32.GetAsyncKeyState(vk) & 0x8000)
    mods = set()
    if down(VK_CONTROL):
        mods.add(CTRL)
    if down(VK_SHIFT):
        mods.add(SHIFT)
    if down(VK_MENU):
        mods.add(ALT)
    if down(VK_LWIN) or down(VK_RWIN):
        mods.add(WIN)
    return frozenset(mods)


class WindowsEnforcer:
    def __init__(self, guard: Guard, log_error: Callable[[str], None] = print):
        self.guard = guard
        self.log_error = log_error
        self._thread_id = 0
        self._hooks: list = []
        self._hwnd = None
        # Keep references so ctypes callbacks are not garbage collected.
        self._kb_proc = HOOKPROC(self._keyboard_proc)
        self._ms_proc = HOOKPROC(self._mouse_proc)
        self._wnd_proc = WNDPROC(self._window_proc)

    # -------------------------------------------------------------- hooks
    # Any exception inside a hook fails OPEN (event passes) so a bug can
    # never leave the machine without a usable keyboard or mouse.

    def _keyboard_proc(self, n_code, w_param, l_param):
        try:
            if n_code == HC_ACTION:
                kb = ctypes.cast(l_param, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
                is_down = w_param in (WM_KEYDOWN, WM_SYSKEYDOWN)
                if w_param in (WM_KEYDOWN, WM_SYSKEYDOWN, WM_KEYUP, WM_SYSKEYUP):
                    fg = lambda: process_of_window(user32.GetForegroundWindow())
                    if self.guard.handle_key(kb.vkCode, is_down, _pressed_modifiers(), fg):
                        return 1
        except Exception as exc:  # pragma: no cover
            self.log_error(f"keyboard hook error: {exc!r}")
        return user32.CallNextHookEx(None, n_code, w_param, l_param)

    def _mouse_proc(self, n_code, w_param, l_param):
        try:
            if n_code == HC_ACTION:
                ms = ctypes.cast(l_param, ctypes.POINTER(MSLLHOOKSTRUCT)).contents
                x, y = ms.pt.x, ms.pt.y
                if w_param in (WM_LBUTTONDOWN, WM_RBUTTONDOWN):
                    self.guard.mouse_down(x, y)
                elif w_param in (WM_LBUTTONUP, WM_RBUTTONUP):
                    self.guard.mouse_up()
                elif w_param == WM_MOUSEMOVE:
                    origin = self.guard.drag_origin or (x, y)

                    def under_cursor():
                        hwnd = user32.WindowFromPoint(wt.POINT(*origin))
                        return process_of_window(user32.GetAncestor(hwnd, GA_ROOT) or hwnd)

                    if self.guard.mouse_move(x, y, under_cursor):
                        return 1
        except Exception as exc:  # pragma: no cover
            self.log_error(f"mouse hook error: {exc!r}")
        return user32.CallNextHookEx(None, n_code, w_param, l_param)

    # ---------------------------------------------------------- clipboard

    def _window_proc(self, hwnd, msg, w_param, l_param):
        if msg == WM_CLIPBOARDUPDATE:
            try:
                self._on_clipboard_update()
            except Exception as exc:  # pragma: no cover
                self.log_error(f"clipboard error: {exc!r}")
            return 0
        return user32.DefWindowProcW(hwnd, msg, w_param, l_param)

    def _on_clipboard_update(self) -> None:
        if user32.CountClipboardFormats() == 0:  # our own EmptyClipboard echo
            return
        owner = process_of_window(user32.GetClipboardOwner())
        if self.guard.clipboard_changed(owner):
            self._empty_clipboard()

    def _empty_clipboard(self) -> None:
        for _ in range(10):  # another process may hold the clipboard briefly
            if user32.OpenClipboard(self._hwnd):
                try:
                    user32.EmptyClipboard()
                finally:
                    user32.CloseClipboard()
                return
            time.sleep(0.02)
        self.log_error("could not open clipboard to clear it")

    def _create_listener_window(self) -> None:
        h_instance = kernel32.GetModuleHandleW(None)
        wc = WNDCLASSW()
        wc.lpfnWndProc = self._wnd_proc
        wc.hInstance = h_instance
        wc.lpszClassName = "EndpointGuardClipboardListener"
        user32.RegisterClassW(ctypes.byref(wc))
        self._hwnd = user32.CreateWindowExW(0, wc.lpszClassName, "EndpointGuard", 0, 0, 0, 0, 0,
                                            HWND_MESSAGE, None, h_instance, None)
        if not self._hwnd or not user32.AddClipboardFormatListener(self._hwnd):
            raise OSError(ctypes.get_last_error(), "failed to register clipboard listener")

    # -------------------------------------------------------------- run

    def run(self, duration: float | None = None) -> None:
        self._thread_id = kernel32.GetCurrentThreadId()
        h_instance = kernel32.GetModuleHandleW(None)
        for hook_id, proc in ((WH_KEYBOARD_LL, self._kb_proc), (WH_MOUSE_LL, self._ms_proc)):
            hook = user32.SetWindowsHookExW(hook_id, proc, h_instance, 0)
            if not hook:
                raise OSError(ctypes.get_last_error(), f"SetWindowsHookExW({hook_id}) failed")
            self._hooks.append(hook)
        self._create_listener_window()
        if self.guard.controls["clipboard"].enabled and not self.guard.dry_run:
            self._empty_clipboard()  # nothing copied before start-up survives
        if duration:
            threading.Timer(duration, self.stop).start()
        msg = wt.MSG()
        try:
            while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
        finally:
            for hook in self._hooks:
                user32.UnhookWindowsHookEx(hook)
            self._hooks.clear()
            if self._hwnd:
                user32.RemoveClipboardFormatListener(self._hwnd)
                user32.DestroyWindow(self._hwnd)

    def stop(self) -> None:
        if self._thread_id:
            user32.PostThreadMessageW(self._thread_id, WM_QUIT, 0, 0)
