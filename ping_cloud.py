# -*- coding: utf-8 -*-
from __future__ import division
from ctypes import *
import socket
import struct
import sys
import os


class IP(Structure):
    _fields_ = [
        ("version", c_ubyte, 4),
        ("tos", c_ubyte, 8),
        ("len", c_ushort, 16),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte, 8),
        ("protocol_num", c_ubyte, 8),
        ("sum", c_ushort, 16),
        ("src", c_uint),
        ("dst", c_uint),
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.protocol_map = {
                    1:"ICMP",
                    6:"TCP",
                    17:"UDP"
                    }

        src = struct.pack("<L", self.src)
        dst = struct.pack("<L", self.dst)
        self.src_address = socket.inet_ntoa(src)
        self.dst_address = socket.inet_ntoa(dst)
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

host = "192.168.0.101"                     #server ip
send_bytes = 1

if os.name == "nt":                         #windows
	socket_protocol = socket.IPPROTO_IP
else:                                       #linux
	socket_protocol = socket.IPPROTO_ICMP            
	
	

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((host,0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
if os.name == "nt":                         #windows
	sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
	
try:
    while 1:
        data = sniffer.recvfrom(65565)[0]
        ip_header = IP(data)
        
        if os.name == "nt":
        	target_ip = ip_header.dst_address
        	your_ip = ip_header.src_address
        else:
        	target_ip = ip_header.src_address
        	your_ip = ip_header.dst_address
        if ip_header.protocol == 'ICMP' and your_ip == host:
        	if ((ip_header.len/1024)*4-28) == send_bytes:                            #targer server send bytes
        		print ip_header.protocol,target_ip,your_ip

except KeyboardInterrupt:
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
except :
	print 'error'
	sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)







