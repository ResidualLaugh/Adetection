# Adetection

通过censys搜索引擎针对使用ssl证书的域名进行资产探测（真实ip）和子域名收集，这种方法可以发现常规资产探测不易发现的站点

用于日常渗透测试工作中

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

