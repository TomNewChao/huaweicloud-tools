# -*- coding: utf-8 -*-
import logging

import huaweicloudsdkcore
import requests
import click
import yaml
from obs import ObsClient
from logging import handlers
from huaweicloudsdkcore.auth.credentials import BasicCredentials, GlobalCredentials
from huaweicloudsdkcore.http.http_config import HttpConfig
from huaweicloudsdkiam.v3 import KeystoneListProjectsRequest, IamClient
from huaweicloudsdkiam.v3.region.iam_region import IamRegion
from huaweicloudsdkvpc.v2 import VpcClient, ListSecurityGroupsRequest
from huaweicloudsdkcore.exceptions import exceptions
from collections import defaultdict

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class Config(object):
    obs_bucket_name = "obs-for-openeuler-developer"
    obs_bucket_key = "secret-files/collect_elastic_public_ip.yaml"
    ecs_endpoint = "https://vpc.{}.myhuaweicloud.com"
    zone_alias_dict = {
        "cn-north-1": "华北-北京一",
        "cn-north-4": "华北-北京四",
        "cn-north-5": "华北-乌兰察布二零一",
        "cn-north-6": "华北-乌兰察布二零二",
        "cn-north-9": "华北-乌兰察布一",
        "cn-east-3": "华东-上海一",
        "cn-east-2": "华东-上海二",
        "cn-south-1": "华南-广州",
        "cn-south-4": "华南-广州-友好用户环境",
        "cn-southwest-2": "西南-贵阳一",
        "ap-southeast-1": "中国-香港",
        "ap-southeast-2": "亚太-曼谷",
        "ap-southeast-3": "亚太-新加坡",
        "af-south-1": "非洲-约翰内斯堡",
        "na-mexico-1": "拉美-墨西哥城一",
        "la-north-2": "拉美-墨西哥城二",
        "sa-brazil-1": "拉美-圣保罗一",
        "la-south-2": "拉美-圣地亚哥",
        "ru-northwest-2": "俄罗斯-莫斯科二",
    }


class Logger(object):
    level_relations = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'crit': logging.CRITICAL
    }

    def __init__(self, filename, level='info', when='D', back_count=3,
                 fmt='%(asctime)s - %(pathname)s[line:%(lineno)d] - %(levelname)s: %(message)s'):
        self.logger = logging.getLogger(filename)
        format_str = logging.Formatter(fmt)
        self.logger.setLevel(self.level_relations.get(level))
        sh = logging.StreamHandler()
        sh.setFormatter(format_str)
        th = handlers.TimedRotatingFileHandler(filename=filename, when=when, backupCount=back_count, encoding='utf-8')
        th.setFormatter(format_str)
        self.logger.addHandler(sh)
        self.logger.addHandler(th)


logger = Logger('get_security_group.log', level='info').logger


class ObsImp(object):
    def __init__(self, ak, sk, url):
        self.obs_client = ObsClient(access_key_id=ak,
                                    secret_access_key=sk,
                                    server=url)

    def get_obs_data(self, download_bucket, download_key):
        """down obs data"""
        content = str()
        resp = self.obs_client.getObject(download_bucket, download_key, loadStreamInMemory=False)
        if resp.status < 300:
            while True:
                chunk = resp.body.response.read(65536)
                if not chunk:
                    break
                content = "{}{}".format(content, chunk.decode("utf-8"))
            resp.body.response.close()
        elif resp.errorCode == "NoSuchKey":
            logger.info("Key:{} is not exist, need to create".format(download_key))
            raise RuntimeError("get object failed(no such key):{}...".format(download_key))
        else:
            logger.error('errorCode:{}'.format(resp.errorCode))
            logger.error('errorMessage:{}'.format(resp.errorMessage))
            raise RuntimeError("get object failed：{}....".format(download_key))
        now_account_info_list = yaml.load(content, Loader=yaml.FullLoader)
        return now_account_info_list


class BaseImp(object):
    def __init__(self):
        self.config = HttpConfig.get_default_config()
        self.config.ignore_ssl_verification = True
        self.config.retry_times = 1
        self.config.timeout = (180, 180)


class IamImp(BaseImp):
    def __init__(self, ak, sk, zone="ap-southeast-1"):
        super(IamImp, self).__init__()
        credentials = GlobalCredentials(ak, sk)
        self.client = IamClient.new_builder().with_http_config(self.config) \
            .with_credentials(credentials) \
            .with_region(IamRegion.value_of(zone)) \
            .build()

    def get_project_zone(self):
        """get the zone and project from iam"""
        list_data = list()
        try:
            request = KeystoneListProjectsRequest()
            response = self.client.keystone_list_projects(request)
            for info in response.projects:
                if info.name in ["cn-northeast-1", "MOS", "ap-southeast-1_tryme", "cn-north-1_1"]:
                    continue
                list_data.append({"zone": info.name, "project_id": info.id})
            logger.info("[get_project_zone] collect project total:{}".format(len(list_data)))
            return list_data
        except exceptions.ClientRequestException as e:
            msg = "[HWCloudIAM] ak:{}, sk:{} get project zone failed:{},{}".format(e.status_code, e.request_id,
                                                                                   e.error_code, e.error_msg)
            logger.error(msg)
            return list_data


class SecurityRuleImp(BaseImp):
    def __init__(self, ak, sk, project_id, endpoint):
        super(SecurityRuleImp, self).__init__()
        credentials = BasicCredentials(ak, sk, project_id)
        self.vpc_client = VpcClient.new_builder() \
            .with_http_config(self.config) \
            .with_credentials(credentials) \
            .with_endpoint(endpoint) \
            .build()

    def query_security_group(self, *args, **kwargs):
        try:
            query_security_group_rq = ListSecurityGroupsRequest(*args, **kwargs)
            ret = self.vpc_client.list_security_groups(query_security_group_rq)
            return ret
        except huaweicloudsdkcore.exceptions.exceptions.HostUnreachableException as e:
            logger.info("[query_security_group] {}".format(e))
            return None
        except huaweicloudsdkcore.exceptions.exceptions.ClientRequestException as e:
            logger.info("[query_security_group] {}".format(e))
            return None

    def parse_security_group(self, security_group, account, zone):
        dict_data = defaultdict(list)
        if security_group is not None:
            security_groups = security_group.security_groups
        else:
            security_groups = list()
        for security_info in security_groups:
            for rule in security_info.security_group_rules:
                remote_ip_prefix = rule.remote_ip_prefix
                # logger.info("find ip:{}".format(remote_ip_prefix))
                if remote_ip_prefix and "/" in remote_ip_prefix:
                    ip = remote_ip_prefix.split("/")[0]
                    if ip == "0.0.0.0" or "::" in ip:
                        continue
                    else:
                        tmp = {
                            "account": account,
                            "zone": zone,
                            "name": security_info.name
                        }
                        dict_data[ip].append(tmp)
        return dict_data

    def security_group(self, account, zone):
        security_groups = self.query_security_group()
        return self.parse_security_group(security_groups, account, zone)


@click.command()
@click.option("--ak", help="the obs ak")
@click.option("--sk", help="the obs sk")
@click.option("--url", help="the obs url")
@click.option("--ip", help="the ip")
def main(ak, sk, url, ip):
    ip_dict = defaultdict(list)
    logger.info("-" * 25 + "start to get config from obs" + "-" * 25)
    obs_imp = ObsImp(ak, sk, url)
    account_info_list = obs_imp.get_obs_data(Config.obs_bucket_name, Config.obs_bucket_key)
    for account_info in account_info_list:
        account_info["project_info"] = IamImp(account_info["ak"], account_info["sk"]).get_project_zone()
    logger.info("-" * 25 + "start to get ip info from security_group" + "-" * 25)
    for account_info in account_info_list:
        account = account_info["account"]
        logger.info("start to get ip from account:{}".format(account))
        for project in account_info["project_info"]:
            endpoint = Config.ecs_endpoint.format(project["zone"])
            zone_alias = Config.zone_alias_dict.get(project["zone"], project["zone"])
            sr_imp = SecurityRuleImp(account_info["ak"], account_info["sk"],
                                     project["project_id"], endpoint)
            ip_dict_temp = sr_imp.security_group(account, zone_alias)
            for ip_temp, info_list in ip_dict_temp.items():
                ip_dict[ip_temp].extend(info_list)
    sg_info = ip_dict.get(ip)
    logger.info("-" * 2 + "start to output the info of ip:{}".format(ip) + "-" * 2)
    if sg_info:
        for sg_dict in sg_info:
            logger.info("There find ip:{},account:{},zone:{},name:{}".format(ip, sg_dict["account"],
                                                                             sg_dict["zone"], sg_dict["name"]))
    else:
        logger.info("The ip info is not exist")


if __name__ == '__main__':
    main()
