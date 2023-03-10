# -*- coding: utf-8 -*-
# @Time    : 2022/6/7 10:33
# @Author  : Tom_zc
# @FileName: security_group_vpc.py
# @Software: PyCharm
import argparse
import copy
import json
import re
import socket
import requests
import time

from functools import wraps
from collections import defaultdict

from huaweicloudsdkcore.exceptions.exceptions import ClientRequestException
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkcore.http.http_config import HttpConfig
from huaweicloudsdkvpc.v2 import VpcClient, ListSecurityGroupRulesRequest, CreateSecurityGroupRuleRequest, \
    DeleteSecurityGroupRuleRequest, CreateSecurityGroupRequest, ListSecurityGroupsRequest

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class GlobalConfig(object):
    default_security_group = "openeuler-community-cce-node-ci-prod"


class Domain(object):
    huawei_cloud_domain = "repo.huaweicloud.com"
    gitee_domain = "gitee.com"
    s3_gitee_domain = "s3.gitee.com"

    @classmethod
    def get_domain_template(cls):
        return {
            cls.huawei_cloud_domain: {
                'description': cls.huawei_cloud_domain,
                'security_group_id': '',
                'direction': 'egress',
                'ethertype': 'IPv4',
                'protocol': 'tcp',
                'port_range_min': 443,
                'port_range_max': 443,
                'remote_ip_prefix': '',
                'remote_group_id': None
            },
            cls.gitee_domain: {
                'description': cls.gitee_domain,
                'security_group_id': '',
                'direction': 'egress',
                'ethertype': 'IPv4',
                'protocol': None,
                'port_range_min': None,
                'port_range_max': None,
                'remote_ip_prefix': '',
                'remote_group_id': None

            },
            cls.s3_gitee_domain: {
                'description': cls.s3_gitee_domain,
                'security_group_id': '',
                'direction': 'egress',
                'ethertype': 'IPv4',
                'protocol': None,
                'port_range_min': None,
                'port_range_max': None,
                'remote_ip_prefix': '',
                'remote_group_id': None

            }
        }

    @classmethod
    def is_in_domain(cls, domain):
        if domain in cls.get_domain_template().keys():
            return True
        else:
            return False


def func_retry(tries=3, delay=1):
    def deco_retry(fn):
        @wraps(fn)
        def inner(*args, **kwargs):
            for i in range(tries):
                try:
                    return fn(*args, **kwargs)
                except Exception as e:
                    print(e)
                    time.sleep(delay)
            else:
                raise Exception("func_retry: {} failed".format(fn.__name__))

        return inner

    return deco_retry


class VPCInstance(object):

    def __init__(self, config, credentials, endpoint):
        self.vpc_client = VpcClient.new_builder() \
            .with_http_config(config) \
            .with_credentials(credentials) \
            .with_endpoint(endpoint) \
            .build()

    def query_security_group(self, *args, **kwargs):
        query_security_group_rq = ListSecurityGroupsRequest(*args, **kwargs)
        return self.vpc_client.list_security_groups(query_security_group_rq)

    def create_security_group(self, *args, **kwargs):
        create_security_group_rq = CreateSecurityGroupRequest(*args, **kwargs)
        return self.vpc_client.create_security_group_rule(create_security_group_rq)

    def query_security_group_rule(self):
        query_security_group_rule_rq = ListSecurityGroupRulesRequest()
        return self.vpc_client.list_security_group_rules(query_security_group_rule_rq)

    def create_security_group_rule(self, *args, **kwargs):
        create_security_group_rule_rq = CreateSecurityGroupRuleRequest(*args, **kwargs)
        return self.vpc_client.create_security_group_rule(create_security_group_rule_rq)

    def delete_security_group_rule(self, *args, **kwargs):
        delete_security_group_rule_rq = DeleteSecurityGroupRuleRequest(*args, **kwargs)
        return self.vpc_client.delete_security_group_rule(delete_security_group_rule_rq)


# noinspection PyNestedDecorators,PyMethodMayBeStatic
class VPCTools(object):
    def __init__(self, *args, **kwargs):
        super(VPCTools, self).__init__(*args, **kwargs)

    @classmethod
    def get_vpc_config(cls):
        config = HttpConfig.get_default_config()
        config.ignore_ssl_verification = True
        return config

    @classmethod
    def parse_input_args(cls):
        par = argparse.ArgumentParser()
        par.add_argument("-ak", "--ak", help="The ak of huawei-cloud", required=True)
        par.add_argument("-sk", "--sk", help="The sk of huawei-cloud", required=True)
        par.add_argument("-end_point", "--end_point", help="The end_point of huawei-cloud", required=True)
        par.add_argument("-project_id", "--project_id", help="The project id of object", required=True)
        args = par.parse_args()
        return args

    @func_retry()
    def parse_gitee_ip_list(self, domain):
        ip_list = []
        addr_list = socket.getaddrinfo(domain, None)
        for item in addr_list:
            if item[4][0] not in ip_list:
                ip_list.append(item[4][0])
        if not len(ip_list):
            raise Exception("get gitee ip list failed")
        return ip_list

    @func_retry()
    def update_ip_white_list(self, security_group_dict, vpc_tools, vpc_instance):
        exist_sg_rule_dict = defaultdict(set)
        exist_sg_rule_set, not_change_rule_set = set(), set()
        for security_group in security_group_dict['security_groups']:
            if security_group['name'] != GlobalConfig.default_security_group:
                continue
            print("The current security group name:{}".format(security_group['name']))
            for security_group_rules in security_group['security_group_rules']:
                if not security_group_rules['description'] or not Domain.is_in_domain(
                        security_group_rules['description'].strip()):
                    continue
                if security_group_rules['direction'] != "egress":
                    continue
                print("The current security group rule id:{}".format(security_group_rules['id']))
                exist_sg_rule_set.add(security_group_rules['id'])
                description_domain = security_group_rules['description'].strip()
                exist_sg_rule_dict[description_domain].add(security_group_rules['security_group_id'])
        exist_list_dict = {key: list(value) for key, value in exist_sg_rule_dict.items()}
        need_create_domain_template_dict = Domain.get_domain_template()
        for domain, domain_template in need_create_domain_template_dict.items():
            if domain not in exist_list_dict.keys():
                continue
            ip_white_list = vpc_tools.parse_gitee_ip_list(domain)
            for ip_white in ip_white_list:
                temp_dict = copy.deepcopy(domain_template)
                temp_dict['remote_ip_prefix'] = r"{}/32".format(ip_white)
                if len(exist_list_dict[domain]) == 0:
                    continue
                else:
                    temp_dict['security_group_id'] = exist_list_dict[domain][0]
                body_data = {"security_group_rule": temp_dict}
                try:
                    ret = vpc_instance.create_security_group_rule(body=body_data)
                    ret_dict = ret.to_dict()
                    print("Security group rule created successfully:{}".format(ret_dict['security_group_rule']['id']))
                except ClientRequestException as e:
                    error_dict = json.loads(e.error_msg)
                    if error_dict['NeutronError']['type'] == "SecurityGroupRuleExists":
                        msg = error_dict['NeutronError']['message']
                        search_msg = re.search(r"Rule id is ([-_0-9a-zA-Z]*)", msg)
                        if search_msg is None:
                            raise Exception("Security group rule return invalid params:{}".format(msg))
                        security_group_rules_id = search_msg.group().split("Rule id is ")[1]
                        not_change_rule_set.add(security_group_rules_id)
                    else:
                        raise Exception("create security group rule failed")
        ret = list(exist_sg_rule_set - not_change_rule_set)
        print("exist_sg_rule_list   :{}".format(",".join([i for i in list(exist_sg_rule_set)])))
        print("not_change_rule_list :{}".format(",".join([i for i in list(not_change_rule_set)])))
        print("need_delete_rule_list:{}".format(",".join(ret)))
        return ret


def main():
    # 1.配置
    vpc_tools = VPCTools()
    input_args = vpc_tools.parse_input_args()
    ak = input_args.ak
    sk = input_args.sk
    endpoint = input_args.end_point
    project_id = input_args.project_id
    print("##################1.parse input params################")
    config = vpc_tools.get_vpc_config()
    credentials = BasicCredentials(ak, sk, project_id)
    vpc_instance = VPCInstance(config, credentials, endpoint)
    # 2.获取策略信息
    print("##################2.parse gitee ip################")
    security_group_response = vpc_instance.query_security_group(limit=100)
    security_group_dict = security_group_response.to_dict()
    if security_group_dict.get("security_groups") is None:
        raise Exception("Get security group failed, Security group is None")
    # 3.先查询出指定安全组的规则，通过describe来进行更新，并删除之前已经存在的规则。
    print("##################3.total security group rules################")
    need_delete_sg_rule_list = vpc_tools.update_ip_white_list(security_group_dict, vpc_tools, vpc_instance)
    print("##################4.delete security group rules################")
    for rule_id in need_delete_sg_rule_list:
        vpc_instance.delete_security_group_rule(security_group_rule_id=rule_id)
        print("Security group rule deleted successfully:{}".format(rule_id))


if __name__ == "__main__":
    main()
