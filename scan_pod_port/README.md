# scan-pod-port

# 功能介绍
用于扫描pod暴露的端口，然后通过容器查看打印结果（通过标准输出查看结果）

# 执行命令
./start.bash namespace /root/kubeconfig.yaml

namespace: 命名空间

/root/kubeconfig.yaml: kuebconfig配置文件的路径

注意：执行脚本前需要安装kubectl

详细见： https://juejin.cn/s/yum%20install%20kubectl%20centos8

# 脚本流程：
1.通过kubeconfig和namespace创建deployment任务。 

2.通过kubectl cp ./deploy.yaml 拷贝到pod中

3.通过kubectl exec -it /bin/bash python3 scan_pod_port.py

4.通过kubectl logs查看执行结果

