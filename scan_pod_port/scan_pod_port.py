# -*- coding: utf-8 -*-
# @Time    : 2023/7/7 9:00
# @Author  : Tom_zc
# @FileName: scan_pod_port.py.py
# @Software: PyCharm
import os
import click
import subprocess
from enum import Enum
from collections import defaultdict
from prettytable import PrettyTable


class GlobalConfig(Enum):
    get_service_cmd = "kubectl get pod -o wide -n {} --kubeconfig={}"
    scan_tcp_port = "nmap -sT {}"
    scan_udp_port = "nmap -sU {}"


def exit_process():
    exit(-1)


def parse_service(content):
    dict_data = dict()
    line_list = content.split("\n")
    for line in line_list:
        fileds_list = line.split(" ")
        fileds_list = [i for i in fileds_list if i]
        if len(fileds_list) < 9:
            print("find fileds list length lt 9:{}".format(fileds_list))
            continue
        name = fileds_list[0]
        name = name.rsplit(sep="-", maxsplit=1)[0]
        name = name.rsplit(sep="-", maxsplit=1)[0]
        ip = fileds_list[5]
        dict_data[name] = ip
    if "NAME" in dict_data.keys():
        del dict_data["NAME"]
    return dict_data


def get_service(namespace, kubeconfig):
    cmd = GlobalConfig.get_service_cmd.value.format(namespace, kubeconfig)
    code, data = subprocess.getstatusoutput(cmd)
    if code != 0:
        print("get service failed:{}".format(data))
        exit_process()
    dict_data = parse_service(data)
    return dict_data


def parse_ip(content):
    port_set = set()
    line_list = content.split("\n")
    is_over_length = False
    for line in line_list:
        if line.starts("PORT"):
            is_over_length = True
        if is_over_length:
            fileds_list = line.strip(" ")
            if len(fileds_list) == 3:
                port = fileds_list[0]
                port_set.add(port)
    return list(port_set)


def scan_ip(cmd):
    code, data = subprocess.getstatusoutput(cmd)
    if code != 0:
        print("scan ip failed:{}".format(data))
        exit_process()
    port_list = parse_ip(data)
    return port_list


def get_port_list(ip):
    port_list = list()
    cmd = GlobalConfig.scan_tcp_port.value.format(ip)
    tcp_port_list = scan_ip(cmd)
    port_list.append(tcp_port_list)
    cmd = GlobalConfig.scan_udp_port.value.format(ip)
    udp_port_list = scan_ip(cmd)
    port_list.append(udp_port_list)
    port_list = list(set(port_list))
    return port_list


def get_port(ip_dict):
    new_dict = defaultdict(list)
    for name, ip in ip_dict.items():
        key = (name, ip)
        port_list = get_port_list(ip)
        new_dict[key].append(port_list)
    return new_dict


def console_info(info_dict):
    tb = PrettyTable()
    tb.field_names = ["Name", "Host", "Ports"]
    tb.title = "Scan Containers Ports"
    for key, port_list in info_dict:
        name, host = key
        tb.add_row([name, host, ",".join(port_list)])
    print(tb)


@click.command()
@click.option("--kubeconfig", help="the path of kubeconfig",
              default=r"/opt/scan_pod_port/kubeconfig.yaml")
@click.option("--namespace", help="the namespace of k8s", default=os.getenv("NAMESPACE", None))
def main(kubeconfig, namespace):
    kubeconfig = kubeconfig.strip()
    namespace = namespace.strip()
    if not os.path.exists(kubeconfig):
        raise RuntimeError("kubeconfig is not exist:{}".format(kubeconfig))
    if not namespace:
        raise RuntimeError("invalid namespace:{}".format(namespace))
    ip_dict = get_service(namespace, kubeconfig)
    info_dict = get_port(ip_dict)
    console_info(info_dict)


if __name__ == '__main__':
    main()
