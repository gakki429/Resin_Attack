# Resin Attack

author: gakki429 date: 2018-7-28

Resin已知的漏洞、弱口令爆破的集成

### 配置文件

    漏洞规则文件 config/rules.txt
    
        规则大概构成为：[漏洞url]:::[漏洞存在的标志]
        以/resin-doc/resource/tutorial/jndi-appconfig/test?inputFile=为例：
            /resin-doc/resource/tutorial/jndi-appconfig/test?inputFile=http://127.0.0.1/?ssrf:::back to demo
            这里是一个ssrf的检测，成功的标志为"back to demo"
        规则是尽力去确认漏洞存在，所以一个点多个测试
    	
    弱口令字典 config/xunfeng_pwd.txt （取自巡风）
    
    默认关闭了报错

### 使用方法

    Usage: python resin_attack.py [options]
    (e.g.: python resin_attack.py -u [http://www.resin.com/ | test.txt])
    
    Options:
      -h, --help            show this help message and exit
      -u URL, --url=URL     Target url or file
      -t THREAD_NUM, --threads=THREAD_NUM
                            Number of threads. default: 10
      -c VULNS, --vulns=VULNS
                            Rules of Resin Poc. default: config/rules.txt
      -d DICT, --dict=DICT  Dict file used to brute Resin. default:
                            config/xunfeng_pwd.txt
      -r REPORTS, --reports=REPORTS
                            Report scan results. default: reports/results.txt
    
    python resin_attacker.py -u http://www.resin.com
    
    简单的循环批量
    python resin_attacker.py -u targets.txt
    
    提供了测试样例targets.txt

### 感谢
使用了[xunfeng](https://github.com/ysrc/xunfeng)的字典和参考了其部分poc
