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
