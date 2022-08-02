# 匿名访问对象存储资源扫描工具： scan_obs

## 1.背景

​		对华为云的对象系统（简称OBS）的安全整改，存在着关键信息的泄露，为了防范风险，特此开发此工具来扫描风险点。

## 2.需求

​		扫描openEuler等开源社区使用的所有华为云账户，将所有匿名的桶扫描出来，何为匿名桶？就是桶的策略设置为匿名用户，或者桶的ACL设置为匿名用户，再对匿名桶里的敏感文件后缀名的进行扫描，默认是scan_obs.yaml的sensitive_file_suffix字段；并对扫描出来的文件，下载后经cocoNLP提取邮箱、手机号、关键姓名等，并将扫描的数据保存为CSV文件。

## 3.使用

1.安装软件和依赖包，安装时请注意安装软件与环境上已安装软件的兼容性。

~~~bash
yum -y install gcc-c++
yum -y install python3-devel
yum -y install java-1.8.0-openjdk*

pip3 install esdk-obs-python --trusted-host pypi.org
pip3 install cocoNLP==0.0.11
pip3 install argcomplete
pip3 install phonenumbers
pip3 install python-stdnum
pip3 install textblob
pip3 install jpype1
pip3 install arrow
~~~

2.修改配置文件:scan_obs.yaml

~~~bash
check_bucket: true   # 扫描匿名的桶，默认打开
check_sensitive_file: true   # 扫描匿名的桶中的敏感文件，默认打开
check_sensitive_content: false   #对扫描匿名的桶中的敏感文件提取敏感数据，默认关闭。
sensitive_file_suffix: ["sh", "java", "jsp", "log", "sql", "conf", "cer", "php", "php5", "asp", "cgi", "aspx", "war", "bat","c", "cc", "cpp", "cs", "go", "lua", "perl", "pl","py", "rb", "vb", "vbs", "vba", "h", "jar", "properties","config", "class"]
high_risk_action: [ "DeleteBucket", "PutBucketPolicy", "DeleteBucketPolicy", "Put*", "PutBucketLogging", "PutLifecycleConfiguration", "PutBucketWebsite", "DeleteBucketWebsite", "PutBucketVersions",
                    "PutBucketCORS", "PutBucketAcl", "PutBucketVersioning", "PutBucketInventoryConfiguration", "DeleteBucketInventoryConfiguration", "PutBucketStoragePolicy", "PutReplicationConfiguration", "DeleteReplicationConfiguration",
                    "PutBucketTagging", "DeleteBucketTagging", "PutBucketQuota", "PutBucketCustomDomainConfiguration", "DeleteBucketCustomDomainConfiguration", "PutDirectColdAccessConfiguration", "DeleteDirectColdAccessConfiguration","PutEncryptionConfiguration" ] 
                    # 匿名用户对桶的行为权限
account_info:
- account: 华为云账户1
  ak:  华为云账户1的ak
  sk:  华为云账户1的sk

- account: 华为云账户2
  ak:  华为云账户2的ak
  sk:  华为云账户2的sk
~~~

3.执行命令

~~~bash
python3 scan_obs.py
~~~