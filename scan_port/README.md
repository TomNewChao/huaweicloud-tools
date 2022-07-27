# 端口扫描工具：scan_port

## 1.背景

​		在对华为云进行安全整改，会涉及到端口暴露风险，这就涉及到端口扫描，所以提出对华为云的所有的账户下的管理的的IP进行端口扫描。

## 2.需求

​		根据配置信息获取有的华为云账户下的公网eip, 并使用nmap工具对指定的ip扫描，分别对改ip的tcp, udp进行nmap扫描，并对tcp扫描的端口使用http协议请求，检查是否能获取后端服务的版本号。

## 3.使用

1.安装软件

~~~bash
yum install nmap
pip3 install huaweicloudsdkeip
pip3 install huaweicloudsdknat
pip3 install huaweicloudsdkelb
pip3 install huaweicloudsdkbms
pip3 install huaweicloudsdkecs
pip3 install huaweicloudsdkrds
pip3 install huaweicloudsdkvpc
pip3 install openpyxl
pip3 install PyYAML
~~~

2.修改配置文件： scap_ips.yaml

~~~BASH
- account: 华为云账户1
  ak: 华为云账户1的ak
  sk: 华为云账户1的sk
  project_info:
    - project_id:  华为云账户1的项目id1
      zone: 华为云账户1的项目区域1； 例如：cn-north-1
    - project_id: 华为云账户1的项目id2
      zone: 华为云账户1的项目区域2

- account: 华为云账户2
  ak: 华为云账户2的ak
  sk: 华为云账户2的sk
  project_info:
    - project_id:  华为云账户2的项目id1
      zone: 华为云账户2的项目区域1
    - project_id: 华为云账户2的项目id2
      zone: 华为云账户2的项目区域2
~~~

3.执行脚本

~~~bash
python3 scan_ips.py 
即可输出：公网IP端口扫描统计表.xlsx
~~~

