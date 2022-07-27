# 华为云安全策略组更新工具: security_group

## 1.背景

​		码云的ip会处于不断变化的，华为云到码云的安全策略出规则也会处于不断更新中，所有需要工具刷新安全策略规则。

## 2.需求

​	  以命令行的方式接收参数，先查询指定账户下的所有安全策略，筛选出指定的安全策略组名为openeuler-community-cce-node-ci-prod的策略组，从中解析出方向的安全策略规则，筛选描述为repo.huaweicloud.com和gitee.com的规则；获取repo.huaweicloud.com和gitee.com的真实ip， 根据真实ip生成模板，判断模板是否存在，如果不存在则进行创建规则。

## 3.使用

1.安装软件，执行./install.sh

~~~bsh
#！/bin/bash

is_exist_huaweicloudsdkcore=`pip3 list |grep huaweicloudsdkcore`
is_exist_huaweicloudsdkecs=`pip3 list |grep huaweicloudsdkecs`
is_exist_huaweicloudsdkvpc=`pip3 list |grep huaweicloudsdkvpc`
if [[ -z $is_exist_huaweicloudsdkcore ]]; then
  pip3 install huaweicloudsdkcore
fi

if [[ -z $is_exist_huaweicloudsdkecs ]]; then
  pip3 install huaweicloudsdkecs
fi
if [[ -z $is_exist_huaweicloudsdkvpc ]]; then
  pip3 install huaweicloudsdkvpc
fi

wget https://github.com/Open-Infra-Ops/huaweicloud-tool/raw/main/security_group/security_group_vpc.py
~~~

2.执行脚本

~~~bash
python3 security_group_vpc.py -ak ***** -sk ****** -project_id ****** -end_point https://vpc.cn-north-4.myhuaweicloud.combash
~~~

