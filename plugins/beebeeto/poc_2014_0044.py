#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import md5
import urllib2

from baseframe import BaseFrame

class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0044',  # 由Beebeeto官方编辑
            'name': 'Discuz x3.0 /static/image/common/mp3player.swf 跨站脚本漏洞 POC',  # 名称
            'author': 'tmp',  # 作者
            'create_date': '2014-09-30',  # 编写日期
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',  # 该漏洞所涉及的协议名称
            'port': [80],  # 该协议常用的端口号，需为int类型
            'layer4_protocol': ['tcp'],  # 该协议
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Discuz',  # 漏洞所涉及的应用名称
            'vul_version': ['3.0'],  # 受漏洞影响的应用版本
            'type': 'Cross Site Scripting',  # 漏洞类型
            'tag': ['XSS漏洞', 'mp3player.swf', 'Discuz漏洞', 'FlashXSS'],  # 漏洞相关tag
            'desc': 'Discuz X3.0 static/image/common/mp3player.swf文件存在FlashXss漏洞。',  # 漏洞描述
            'references': ['http://www.ipuman.com/pm6/138/',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        flash_md5 = "f73b6405a9bb7a06ecca93bfc89f8d81"
        file_path = "/static/image/common/mp3player.swf"
        verify_url = args['options']['target'] + file_path
        if args['options']['verbose']:
            print '[*] Requst URL: ' + verify_url
        request = urllib2.Request(verify_url)
        response = urllib2.urlopen(request)
        content = response.read()
        md5_value = md5.new(content).hexdigest()
        if md5_value in flash_md5:
            args['success'] = True
            args['vul_url'] = verify_url
            return args
        args['success'] = False
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())