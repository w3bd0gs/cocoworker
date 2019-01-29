#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urllib2

from baseframe import BaseFrame
from distutils.version import LooseVersion


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0215',
            'name': 'Misfortune Cookie(CVE-2014-9222) POC',
            'author': 'e3rp4y',
            'create_date': '2014-12-22',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Route',
            'vul_version': ['<=4.34'],
            'type': 'Other',
            'tag': ['Misfortune Cookie', 'RomPager', '厄运Cookie漏洞', 'CVE-2014-9222'],
            'desc': '攻击者能够利用Misfortune Cookie漏洞, 将带有攻击负载的cookie发送到服务端, 获取管理员控制权限',
            'references': [
                'http://mis.fortunecook.ie/',
                'https://news.ycombinator.com/item?id=8770662',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = '%s/Allegro' % args['options']['target']
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        ver = re.findall('RomPager Advanced Version (\d+\.\d+)<br>', content)
        if ver and '<title>Allegro Copyright</title>' in content:
            if LooseVersion(ver[0]) < LooseVersion('4.34'):
                args['success'] = True
                args['poc_ret']['vul_url'] = verify_url
            else:
                args['success'] = False
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())