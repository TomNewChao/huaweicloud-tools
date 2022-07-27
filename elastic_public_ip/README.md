# 华为云弹性公网扫描工具: elastic_public_ip

## 1.背景

​		为了我们的运维人员及时通过公网ip，找到公网ip对应的绑定实例，从而可以快速的找到对应的服务，提供工作效率而开发的。

## 2.需求

​		读取配置文件的账号信息，根据账户信息查询公网ip，再根据公网ip遍历所有的绑定资源，输出为excel文档。

## 3.使用

1.安装, 使用install.sh脚本

~~~bash
#！/bin/bash

packages=(
  huaweicloudsdkeip
  huaweicloudsdknat
  huaweicloudsdkelb
  huaweicloudsdkbms
  huaweicloudsdkecs
  huaweicloudsdkrds
  huaweicloudsdkvpc
  openpyxl
  PyYAML
)
for ((i=0;i<${#packages[*]};i++))
do
  temp=`pip3 list |grep ${packages[i]}`
  if [[ -z $temp ]]; then
    pip3 install ${packages[i]}
  fi
done

wget https://github.com/Open-Infra-Ops/huaweicloud-tool/raw/main/elastic_public_ip/collect_elastic_public_ip.py
~~~

2.使用，提供两种方式，一种是命令行方式，一种是加载配置方式

~~~bash
1.命令行方式
python3 collect_elastic_public_ip.py -ak xxxxxxxxxxxxxxxxxx -sk xxxxxxxxxxxxxxxxxx -project_id xxxxxxxxxxxxxxxxxx -zone cn-north-4

2.加载配置的方式
	1.修改collect_elastic_public_ip.yaml配置
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
		
	
	2.执行命令
	python3 collect_elastic_public_ip_by_yaml.py
	输出：公网IP统计表.xlsx
~~~