#!/usr/bin/env bash

namespace=$1
kubeconfig_path=$2

echo "------------start------------"
cur_pod=`kubectl get pod -n ${namespace} --kubeconfig=${kubeconfig_path}|grep scan-containers-port|wc -l`
if [[ ${cur_pod} -ne 0 ]];then
  echo "The scan-containers-port is exist"
  exit -1
fi
cp deploy.yaml deploy_demo.yaml
sed -i "s/namespacevalue/${namespace}/g" deploy_demo.yaml
kubectl apply -f deploy_demo.yaml -n ${namespace} --kubeconfig=${kubeconfig_path}
sleep 10
cur_pod=`kubectl get pod -n ${namespace} --kubeconfig=${kubeconfig_path}|grep scan-containers-port|cut -d " " -f 1`
echo "current pod:$cur_pod"
cp $kubeconfig_path kubeconfig.yaml
sed -i "s/current-context: external/current-context: internal/g" kubeconfig.yaml
kubectl cp kubeconfig.yaml ${cur_pod}:/opt/scan_pod_port/kubeconfig.yaml -n ${namespace} --kubeconfig=${kubeconfig_path}
kubectl exec -it ${cur_pod} /usr/bin/python3 /opt/scan_pod_port/scan_pod_port.py ${namespace} -n ${namespace} --kubeconfig=${kubeconfig_path}
kubectl logs ${cur_pod} -n ${namespace} --kubeconfig=${kubeconfig_path}
kubectl delete deployment scan-containers-port -n ${namespace} --kubeconfig=${kubeconfig_path}
rm -rf deploy_demo.yaml
rm -rf kubeconfig.yaml
