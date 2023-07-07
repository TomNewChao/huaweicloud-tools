#!/usr/bin/env bash

namespace=$0
kubeconfig_path=$1

echo "------------start------------"
cp deploy.yaml deploy_demo.yaml
sed -i ${namespace} deploy_demo.yaml
sed -i ${kubeconfig_path} deploy_demo.yaml
kubectl apply -f deploy_demo.yaml -n ${namespace} --kubeconfig=${kubeconfig_path}
example_pod
kubectl cp $kubeconfig_path ${example_pod}:/opt/scan_pod_port/kubeconfig.yaml -n ${namespace} --kubeconfig=${kubeconfig_path}
kubectl kubectl exec -it ${example_pod} /bin/bash python3 /opt/scan_pod_port/scan_pod_port.py --namespace=${namespace} -n ${namespace} --kubeconfig=${kubeconfig_path}
kubectl kubectl logs ${example_pod} -n ${namespace} --kubeconfig=${kubeconfig_path}
echo "------------end------------"
