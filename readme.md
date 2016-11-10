ping_cloud 用icmp协议监听有哪些服务器ping过自己的服务器，可以检测一些没有回显的远程命令执行漏洞。
根据目标服务器的ip地址和ping命令发包字节判断ping命令是否执行成功。
ping -l 1  (on windows send 1 bytes)
ping -s 1  (on ubuntu send 1 bytes)

修改host为自己的vps地址，send_bytes为自己定义的发包字节数，root 权限运行。如果目标服务器ping命令执行成功，会在本地显示目标服务器的ip等信息。