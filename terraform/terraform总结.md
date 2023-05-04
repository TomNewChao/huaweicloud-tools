## 深入浅出Terraform

## 1.安装

#### 1.安装

~~~bash
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo
sudo yum install terraform
~~~

#### 2.使用

~~~bash
https://www.terraform.io/
~~~

## 2.使用terraform创建华为云虚拟机

### 1.创建一台简单的虚拟机

#### 1.华为云配置~准备

Terraform使用前首先需要配置Provider，配置provider有两种方式：一种是使用AK/SK鉴权，一种是使用用户名/密码方式鉴权。为了安全起见，我们推荐使用AK/SK方式， 配置模板如下：

```
provider "huaweicloud" {
  tenant_name = "tenant"
  # the auth url format follows: https://iam.{region_id}.myhwclouds.com:443/v3
  auth_url    = "https://iam.cn-north-1.myhwclouds.com/v3" 
  region      = "cn-north-1"  
  access_key  = "access key"
  secret_key  = "secret key"
}
```

上面模板中的值需要根据你的账号信息修改，其中特别注意：auth_url 根据region不同修改相应的region_id 部分，详细参见注释部分。

#### 2.配置虚拟机

配置云上任何资源，首先建议了解相应资源的业务，比如虚拟机，涉及到如下几个方面的业务配置：

1. 虚拟机所处的网络——是配置虚拟私有云多台虚机共享公网网络还是直接配置EIP提供公网业务。
2. 虚拟机的规格——主要是配置虚拟机的vCPU个数以及内存大小。
3. 安全组规则——允许开通那些业务端口。
4. 虚拟机镜像——使用什么类型操作以及操作系统的版本，当然也可以使用私有的衍生操作系统。
5. 附加磁盘——是否需要额外挂载数据盘提供存储空间。
6. 其它配置

在了解了这些之后，根据自身业务去配置相应的附加资源，这里本着通用、简单的原则选取私有虚拟云不附带磁盘的场景进行演示。

确定了业务场景后，开始准备相应的资源。首先是网络，网络这里采用最简单的组网方式，一个VPC下一个subnet。在这里有两种选择，一种是使用OpenStack的网络模型：[router](https://www.terraform.io/docs/providers/huaweicloud/r/networking_router_v2.html), [network](https://www.terraform.io/docs/providers/huaweicloud/r/networking_network_v2.html), [subnet](https://www.terraform.io/docs/providers/huaweicloud/r/networking_subnet_v2.html)。[interface](https://www.terraform.io/docs/providers/huaweicloud/r/networking_router_interface_v2.html)另一种是使用华为云简化的网络模型：[vpc](https://www.terraform.io/docs/providers/huaweicloud/r/vpc_v1.html), [subnet](https://www.terraform.io/docs/providers/huaweicloud/r/vpc_subnet_v1.html), 对于前者，要稍微复杂一些，我们以此为例进行介绍，大致的模板如下：

```
resource "huaweicloud_networking_router_v2" "router" {
  name             = "router_example"
  admin_state_up   = "true"
}

resource "huaweicloud_networking_network_v2" "network" {
  name           = "network_example"
  admin_state_up = "true"
}

resource "huaweicloud_networking_subnet_v2" "subnet" {
  name            = "subnet_example"
  network_id      = "${huaweicloud_networking_network_v2.network.id}"
  cidr            = "172.10.100.0/24"
  ip_version      = 4
  dns_nameservers = ["100.125.1.250", "114.114.115.115"]
}

resource "huaweicloud_networking_router_interface_v2" "interface" {
  router_id = "${huaweicloud_networking_router_v2.router.id}"
  subnet_id = "${huaweicloud_networking_subnet_v2.subnet.id}"
}
```

虚拟机规格属于云内置不需要独立创建资源，这里先跳过，虚拟机镜像使用常规的通用镜像，不需要创建资源，关于易用性的提升，我们将在后面介绍。

接下来就是创建虚拟机，虚拟机主要就是[instance](https://www.terraform.io/docs/providers/huaweicloud/r/compute_instance_v2.html)资源，简要配置如下：

```
resource "huaweicloud_compute_instance_v2" "server_example" {
  region = "cn-north-1"
  availability_zone = "cn-north-1a"
  name            = "server_test"
  image_id      = "28accb67-755a-4f0a-b735-e2ad5e437be9"
  flavor_name     = "s2.small.1"
  security_groups = ["default"]

  network {
    uuid = "${huaweicloud_networking_network_v2.network.id}"
  }
  depends_on = ["huaweicloud_networking_router_interface_v2.interface"]
}
```

这样一个可用的虚拟机就创建好了，把上面的脚本放到特定目录执行terraform init， terraform apply就可以在你的账号下创建出一台虚拟机。

### 2.进一步扩展资源

有了第一步的简单脚本后，如果业务不能满足你的诉求，还需要定制更多的资源怎么办？这里以安全组为例，我们以开通常规的80,22端口为例定义一个自定义安全组规则，看下如何扩展资源定义，安全组主要涉及两个资源[secgroup](https://www.terraform.io/docs/providers/huaweicloud/r/networking_secgroup_v2.html), [secgroup_rule](https://www.terraform.io/docs/providers/huaweicloud/r/networking_secgroup_rule_v2.html)配置如下：

```
resource "huaweicloud_networking_secgroup_v2" "sg_example" {
  name        = "sg_example"
  description = "security group for test"
}

resource "huaweicloud_networking_secgroup_rule_v2" "sg_rule_ftp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = "192.168.10.0/24"
  security_group_id = "${huaweicloud_networking_secgroup_v2.sg_example.id}"
}

resource "huaweicloud_networking_secgroup_rule_v2" "sg_rule_http" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 80
  port_range_max    = 80
  remote_ip_prefix  = "192.168.10.0/24"
  security_group_id = "${huaweicloud_networking_secgroup_v2.sg_example.id}"
}
```

定义好以上资源以后，接下来就是需要修改虚拟机中安全组部分的引用上面创建出来的安全组，引用的语法是在资源引号里加 `$(<resource_type>.<resource_name>.<resource_attribute>)`

```
resource "huaweicloud_compute_instance_v2" "server_example" {

  ......  #这里是省略，其它配置不在这里重复显示，并不是一个正确配置
  
  security_groups = ["${huaweicloud_networking_secgroup_v2.sg_example.id}"]

  ......
}
```

这样就实现了虚拟机附属资源的创建及使用。

这里以安全组为例介绍了如何扩展附加资源，对其它的附加资源也类似，建议以文档中的example为模板进行相应修改，具体如何修改需要根据业务以及文档中对各个字段的描述而定。但是方法一样，这里就不再详细介绍了。

### 3.脚本模板化

在这个过程中或许你已经发现，上面写的脚本，每次创建不同业务的虚拟机的时候，需要在不同的脚本中去找参数进行修改，这样有一些麻烦，那么有没有办法把脚本模板化呢，答案当然有。

Terraform配置支持变量，具体介绍参考这里 https://www.terraform.io/docs/configuration/variables.html

有了变量后，我们把配置中常变更的属性值定义成变量集中放到一个tf文件，后续其它文件不需要做修改，只需要更改变量文件就可以了

这里以虚拟机规格为例给一个样例，首先定义一个变量

```
variable "flavor_name" {
    default = "s2.small.1"
    description = "Define the flavor name that will be used to create instance"
}
```

在虚拟机资源中引用该变量而不是写死在这里。

```
resource "huaweicloud_compute_instance_v2" "server_example" {
  ......
  
  flavor_name  = "${var.flavor_name}"
  
  ......
  }
```

实现了变量模板化后，在执行terraform命名时可以指定该变量的值来创建不同规格的虚拟机，如下：

```
terraform apply -var "flavor_name=s1.large.2"
```

### 4.内置资源易用性改进

前一节将配置脚本模板化以后，可以有效将模板编写人员与使用人员角色分开，使得模板编写人是huaweicloud的配置专家，模板使用人员则是业务配置专家。

但是，光这样还是不够，下面来看一个例子，按照上一节我们将镜像进行模板化，最后得到的模板大致会是如下：

```
variable "image" {
    default = "28accb67-755a-4f0a-b735-e2ad5e437be9"
    description = "Define the image that will be used to create instance"
}

variable "flavor_name" {
    default = "s2.small.1"
    description = "Define the flavor name that will be used to create instance"
}
resource "huaweicloud_compute_instance_v2" "server_example" {
  region = "cn-north-1"
  availability_zone = "cn-north-1a"
  name            = "server_test"
  image_id      = "${var.image}"
  flavor_name     = "${var.flavor_name}"
  security_groups = ["default"]

  network {
    uuid = "${huaweicloud_networking_network_v2.network.id}"
  }
  depends_on = ["huaweicloud_networking_router_interface_v2.interface"]
}
```

接下来使用这个脚本模板的人就困惑了——这个Image需要的是一个id，他知道需要哪种类型什么版本的镜像，但是不知道id啊，到哪里去取呢？

那么有没有好的办法只输入一个大概的名称呢？答案肯定，那就是[datasource](https://www.terraform.io/docs/configuration/data-sources.html)

```
data "huaweicloud_images_image_v2" "ubuntu" {
  name = "Ubuntu 16.04 server 64bit"
  most_recent = true
}
resource "huaweicloud_compute_instance_v2" "server_example" {
  region = "cn-north-1"
  availability_zone = "cn-north-1a"
  name            = "server_test"
  image_id      = "${data.huaweicloud_images_image_v2.ubuntu.id}"
  flavor_name     = "${var.flavor_name}"
  security_groups = ["${huaweicloud_networking_secgroup_v2.sg_example.name}"]

  network {
    uuid = "${huaweicloud_networking_network_v2.network.id}"
  }
  depends_on = ["huaweicloud_networking_router_interface_v2.interface"]
}
```

### 5.输出结果

创建完资源后，如何向命令行返回一些资源信息，如创建完虚拟机以后，希望能返回该虚拟机内网IP，Terraform 提供另一个类似资源的定义——[output](https://www.terraform.io/docs/configuration/outputs.html)， 大致定义如下：

```
output "instance_address" {
    value = "${huaweicloud_compute_instance_v2.server_example.access_ip_v4}"
}
```

格式比较简单，只需要定义一个output的名字，然后在value里引用资源的属性即可。

这样当执行完`terraform apply`命令后，命令行会回显如下信息：

```
instance_address = 172.16.10.158
```

到这里，基本的脚本编写涉及的方面就介绍完了。

### 6.资源批量创建

如前面所说，有了上面的的模板后，基本上模板使用者和创建者角色可以分开了，基础的配置基本也就入门了，80%的case都可以应对了，接下来介绍一些更高级的能力。

首先我们看下如何批量创建相同类型的虚拟机，基础模板和单个虚拟机是一样的，唯一要做两件事情，一是定义count属性（批量资源个数），二是解决名称这类不能重复的问题，大致格式如下：

```
resource "huaweicloud_compute_instance_v2" "server_example" {
  .......
  
  count = "2"
  name            = "server_test_${format("%02d",count.index+1)}"
  
  ......
}
```

这里count定义了创建两台虚拟机，name属性里使用了`server_test_`作为前缀，后面跟上批量虚拟机序号作为名称来命名。

当执行terraform plan时，系统将看到两个instance资源，一个叫 server_test_01, 另一个叫server_test_02.

特别注意：批量创建虚拟机的个数不建议设置太大，建议不要超过500，超过这个值后，terraform destroy将耗时很长。

### 7.模块化管理资源

截止到这里，基本常用的都介绍了，更深入将会有这样一个场景，如果terraform管理的系统比较复杂，涉及的资源很多，脚本集中放置管理的话，复杂度将会很大，为了解决这样的问题，terraform提供了[module](https://www.terraform.io/docs/configuration/outputs.html)的机制，将不同业务资源划分为更小的组进行管理，详细请参见官网，这里就不再给例子了。

除了上面介绍的这里功能，其实terraform还有很多处理的函数（如前面用到的format）以及元素查找等能力，这里高级能力需要你熟悉基础后慢慢去探索、使用、熟悉。它们的使用可以提升脚本的易用性，丰富应用场景，但是不一定是必须，如果你掌握了上面介绍的，再配合官方文档介绍，我相信90% case可以很轻松搞定，剩下的也是这篇文章最后要介绍的一个点——如果terraform plan/apply过程中出现错误了怎么定位？

1. 首先设置三个环境变量，linux下命令如下：

```
export TF_LOG=DEBUG
export TF_LOG_PATH=/var/log/terraform.log  #这里是指定日志文件路径
export OS_DEBUG=1
```

1. 再次执行出错的terraform命名后，查看日志文档中ERROR类型错误。它能给你提供非常详细的错误线索。

### 8.本文中可以跑的脚本

- provider.tf AK/SK需要修改

```
provider "huaweicloud" {
  tenant_name = "cn-north-1"
  auth_url    = "https://iam.cn-north-1.myhwclouds.com/v3"
  region      = "cn-north-1"
  insecure    = "true"
  access_key  = "xxxxxxxxx"
  secret_key  = "xxxxxxxxx"
  version = "1.2.0"
}
```

- instance.tf

```
resource "huaweicloud_compute_instance_v2" "server_example" {
  region = "${var.region}"
  availability_zone = "${var.az}"
  name            = "${var.instance_name}"
  image_id      = "${data.huaweicloud_images_image_v2.ubuntu.id}"
  flavor_name     = "${var.flavor_name}"
  security_groups = ["${huaweicloud_networking_secgroup_v2.sg_example.name}"]

  network {
    uuid = "${huaweicloud_networking_network_v2.network.id}"
  }
  depends_on = ["huaweicloud_networking_router_interface_v2.interface"]
}
```

- network.tf

```
resource "huaweicloud_networking_router_v2" "router" {
  name             = "router_example"
  admin_state_up   = "true"
}

resource "huaweicloud_networking_network_v2" "network" {
  name           = "network_example"
  admin_state_up = "true"
}

resource "huaweicloud_networking_subnet_v2" "subnet" {
  name            = "subnet_example"
  network_id      = "${huaweicloud_networking_network_v2.network.id}"
  cidr            = "${var.network_cidr}"
  ip_version      = 4
  dns_nameservers = ["100.125.1.250", "114.114.115.115"]
}

resource "huaweicloud_networking_router_interface_v2" "interface" {
  router_id = "${huaweicloud_networking_router_v2.router.id}"
  subnet_id = "${huaweicloud_networking_subnet_v2.subnet.id}"
}
```

- secutirygroup.tf

```
resource "huaweicloud_networking_secgroup_v2" "sg_example" {
  name        = "${var.sg_name}"
  description = "security group for test"
}

resource "huaweicloud_networking_secgroup_rule_v2" "sg_rule_ftp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = "192.168.10.0/24"
  security_group_id = "${huaweicloud_networking_secgroup_v2.sg_example.id}"
}

resource "huaweicloud_networking_secgroup_rule_v2" "sg_rule_http" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 80
  port_range_max    = 80
  remote_ip_prefix  = "192.168.10.0/24"
  security_group_id = "${huaweicloud_networking_secgroup_v2.sg_example.id}"
}
```

- vars.tf

```
variable "flavor_name" {
    default = "s2.small.1"
    description = "Define the flavor name that will be used to create instance"
}

variable "image_name" {
    default = "Ubuntu 16.04 server 64bit"
    description = "The image of instance that you are going to created"
}

variable "instance_name" {
    default = "example_instance"
    description = "The name of the instance"
}

variable "network_cidr" {
    default = "172.16.10.0/24"
    description = "The network ip range of the network"
}

variable "az" {
    default = "cn-north-1a"
    description = "The availability zone name where the resource will be created"
}

variable "region" {
    default = "cn-north-1"
    description = "The region name where the resource will be created"
}

variable "sg_name" {
    default = "example_sg"
    description = "The name of security name"
}
```

- datasource.tf

```
data "huaweicloud_images_image_v2" "ubuntu" {
  name = "${var.image_name}"
  most_recent = true
}
```

- output.tf

```
output "instance_address" {
    value = "${huaweicloud_compute_instance_v2.server_example.access_ip_v4}"
}
```








