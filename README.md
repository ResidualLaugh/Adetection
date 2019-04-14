# Adetection

通过censys搜索引擎针对使用ssl证书的域名进行资产探测（真实ip）和子域名收集，这种方法可以发现常规资产探测不易发现的站点

用于日常渗透测试工作中

[+] 增加了自定义C段扫描，获取中间件和网站标题

# Install

语言环境

For Python2.7

安装依赖

pip install censys

注册censys账号，替换脚本中的UID和SECRET

# Usage

python Adetection.py target.com

结果会存在当前目录下的txt中

注意：每个免费账号每月仅250次查询机会，不够用的话可以多注册几个


python Cwebscan.py -r target.com_c.txt -p 80,443,8000,5000


# By the way

最近在尝试使用这个脚本，能发现的资产还是很多的，与其他子域名爆破工具互补。

结果中有很多同网段ip，为了能探测更多信息，加入了c段扫描，原项目链接如下

https://github.com/se55i0n/Cwebscanner