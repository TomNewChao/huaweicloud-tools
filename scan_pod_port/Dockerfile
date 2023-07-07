FROM centos:7

MAINTAINER TomNewChao<353712216@qq.com>
ENV PYTHONUNBUFFERED 1

RUN mkdir /opt/scan_pod_port
WORKDIR /opt/scan_pod_port
COPY . /opt/scan_pod_port/
RUN cp /opt/scan_pod_port/kubernetes.repo /etc/yum.repos.d/ && chmod 755 /etc/yum.repos.d/kubernetes.repo
RUN yum update -y && yum install -y gcc-c++ python3 python3-pip python3-devel nmap kubectl git
RUN pip3 install -r /opt/scan_pod_port/requirements.txt
ENV LANG=en_US.UTF-8
ENV PYTHONPATH=/opt/scan_pod_port
CMD ["sleep", "3600"]