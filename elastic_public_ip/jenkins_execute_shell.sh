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