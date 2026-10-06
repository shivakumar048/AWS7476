# Endpoint Guard

A Windows application that restricts **copy, cut, paste, delete and drag & drop**
across the whole system, in every application, for data-loss prevention, kiosks,
exam machines or shared terminals.

Pure Python 3.10+ standard library (it talks to Windows through `ctypes`), so there's nothing to install.

## What it blocks

| Control | Blocked inputs | How |
|---|---|---|
| `copy` | Ctrl+C, Ctrl+Insert | low-level keyboard hook |
| `cut` | Ctrl+X, Shift+Delete | low-level keyboard hook |
| `paste` | Ctrl+V, Shift+Insert, Win+V (clipboard history) | low-level keyboard hook |
| `delete` | Delete, Ctrl+D (Explorer delete); optional folder ACLs | keyboard hook + NTFS deny ACE |
| `drag_drop` | dragging with the left or right mouse button | low-level mouse hook pins the cursor while a button is held |
| `clipboard` | right-click/menu Copy and Paste, programmatic copies | clipboard listener wipes anything placed on the clipboard |
| `screenshot` (off by default) | PrintScreen, Win+Shift+S | low-level keyboard hook |

Shortcuts are matched even with extra modifiers (Ctrl+Shift+C is still blocked).
Normal typing, clicking and selecting with Shift+arrow keys keep working.

Combining `copy`/`paste` with `clipboard` matters: blocking the keys alone still
leaves the right-click menu, and clearing the clipboard closes that path.
For **deletion via menus, scripts or `del`**, use `protected_paths`. They deny
DELETE to *Everyone* on those folders at the file-system level, so nothing can
delete or move files out of them while they can still be opened and edited.

## Quick start (Windows)

```powershell
cd endpoint-guard

# See what a config enforces
python -m guard -c config.example.json status

# Try it safely: log what WOULD be blocked, block nothing, stop after 60 s
python -m guard -c config.example.json run --dry-run --duration 60

# Enforce for 2 minutes, then stop automatically
python -m guard -c config.example.json run --duration 120
```

> While it's enforcing, Ctrl+C can't stop it either (that's the point).
> Use `--duration` when testing, or end the `pythonw.exe` / `python.exe` process from Task Manager.

### Deploy to every user (administrator PowerShell)

```powershell
.\install\install-task.ps1 -Config .\config.example.json   # install
.\install\install-task.ps1 -Uninstall                       # remove
```

The installer:
1. copies the app to `C:\Program Files\EndpointGuard` and the config to `C:\ProgramData\EndpointGuard\config.json`, where standard users can read but not change them;
2. registers a scheduled task that starts the guard in **each user's session at logon** and restarts it if it stops (low-level hooks only work inside the interactive desktop session, which is why this isn't a service);
3. applies delete protection to every folder in `protected_paths`.

Manual folder protection: `python -m guard protect C:\Data\Confidential` and `python -m guard unprotect ...` (elevated).

## Configuration

```json
{
  "dry_run": false,
  "log_file": "C:\\ProgramData\\EndpointGuard\\events.jsonl",
  "controls": {
    "copy":       { "enabled": true },
    "paste":      { "enabled": true },
    "delete":     { "enabled": true, "exempt_processes": ["code.exe"] },
    "drag_drop":  true,
    "screenshot": false
  },
  "exempt_processes": ["keepass.exe"],
  "exempt_users": ["administrator"],
  "drag_threshold": 4,
  "protected_paths": ["C:\\Data\\Confidential"],
  "policy_server": null
}
```

* Each control is `true`/`false` or `{ "enabled": ..., "exempt_processes": [...] }`. Controls you leave out use the defaults: everything except `screenshot` is on.
* `exempt_processes`: executable names where restrictions don't apply. The keyboard checks the foreground app, drag checks the window under the cursor, and the clipboard checks the app that copied.
* `exempt_users`: Windows user names for whom the guard exits immediately.
* `drag_threshold`: pixels the mouse may move with a button held before it counts as a drag. This stops click jitter from being blocked.

Test a config without Windows: `python -m guard -c my.json check ctrl+v --process excel.exe` (exit 0 = blocked).

## Per-user rules from the Logical Access Control server

Endpoint Guard can take its rules per user from the [Logical Access Control](../logical-access-control/README.md)
server in this repo. Set:

```json
"policy_server": { "url": "https://lac.example.internal", "refresh_seconds": 300 }
```

and provide a service account with `lac:SimulatePrincipalPolicy` through the `LAC_USERNAME` / `LAC_PASSWORD`
environment variables. Every `refresh_seconds`, the guard asks whether the logged-on user may perform
`endpoint:Copy`, `endpoint:Cut`, `endpoint:Paste`, `endpoint:Delete`, `endpoint:DragDrop`, `endpoint:Clipboard`
and `endpoint:Screenshot` on `endpoint:host/<computer-name>`. An **Allow** lifts that restriction for the
user; anything else keeps it. If the server can't be reached, the local config stays in force (fail closed).

You don't have to write these policies by hand: the console's **Endpoint rules** screen is a tick-box grid
of groups × actions that writes them for you. Blocked attempts are also sent to the console every 10 seconds
(the service account needs `lac:ReportEndpointEvents`) and appear under **Blocked actions**. Set
`"report_events": false` in `policy_server` to keep events local only.

Example: let the finance team copy and paste, but only on finance PCs.

```json
{ "Statement": [{
    "Effect": "Allow",
    "Action": ["endpoint:Copy", "endpoint:Paste", "endpoint:Clipboard"],
    "Resource": "endpoint:host/FIN-*"
}] }
```

## Event log

Every blocked attempt is appended to `log_file` as JSON:

```json
{"timestamp": "2026-10-06T09:14:03+00:00", "event": "blocked", "user": "bob", "host": "FIN-PC07",
 "control": "copy", "trigger": "Ctrl+C", "process": "excel.exe"}
```

In dry-run mode the event is `would_block`. Key auto-repeat and long drags are logged once.

## Limits (read before relying on it)

User-mode hooks are a strong deterrent, not a security boundary. Pair them with these OS controls:

* **Killing the process:** a standard user can end their own processes. Disable Task Manager with Group Policy
  (*User Configuration → Administrative Templates → System → Ctrl+Alt+Del Options → Remove Task Manager*);
  the scheduled task also restarts the guard within a minute.
* **Elevated windows:** Windows doesn't deliver input for apps running as administrator to a non-elevated hook.
  Don't give restricted users admin rights.
* **Ctrl+Alt+Del** can never be intercepted by any application, and that's by design.
* **Remote Desktop / VM clipboard sharing** is controlled separately: GPO *Do not allow Clipboard redirection*
  and *Do not allow drive redirection*.
* **USB storage:** block it with GPO *Removable Storage Access* or Intune device control.
* Clearing the clipboard also stops copying *within* one application. Exempt apps that need it.
* Blocking drags also blocks selecting text by dragging the mouse, resizing windows by their borders and
  drawing apps. Use double-click or Shift+arrow keys to select text, or exempt those apps from `drag_drop`.
* The hook fails **open**: if an internal error happens, the key or mouse event passes through, so a bug can
  never leave the machine without a working keyboard.

## Tests

```bash
python -m unittest discover -s tests -t .
```

The decision logic, config, CLI and policy-server integration are tested on any OS.
The Windows hook layer (`guard/win32.py`) needs a real Windows session to run.
