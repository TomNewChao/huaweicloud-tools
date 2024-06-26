FROM openeuler/openeuler:22.03
RUN yum update -y && yum install -y gcc-c++ python3 python3-pip python3-devel
RUN pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple
RUN pip config set global.trusted-host pypi.tuna.tsinghua.edu.cn
RUN pip config set global.timeout 120
RUN mkdir /opt/scan_etherpad
COPY . /opt/scan_etherpad/

RUN pip3 install -r /opt/scan_etherpad/requirements.txt
WORKDIR /opt/scan_etherpad
ENV LANG=en_US.UTF-8
ENV PYTHONUNBUFFERED 1
ENV PYTHONPATH=/opt/scan_etherpad/
CMD ["python3", "/opt/scan_etherpad/scan_etherpad.py"]