resource "aws_instance" "instance1" {
    ami = "ami-034a8236c75419857"
    key_name = "amazonlinuxkey"
    instance_type = "t3.micro"
}
