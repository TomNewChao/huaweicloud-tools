# -*- coding: utf-8 -*-
# @Time    : 2022/6/8 17:30
# @Author  : Tom_zc
# @FileName: scan_obs.py
# @Software: PyCharm
import os
import argparse
import time
import yaml
import traceback
from collections import defaultdict
from functools import wraps
from obs.client import ObsClient


# noinspection DuplicatedCode
class GlobalConfig(object):
    base_path = os.path.dirname(__file__)
    scan_obs_result = os.path.join(base_path, "scan_obs_result.txt")
    config_path = os.path.join(base_path, "scan_obs.yaml")

    url = "obs.cn-north-4.myhuaweicloud.com"

    file_postfix = ["sh", "java", "jsp", "log", "sql", "conf", "cer",
                    "php", "php5", "asp", "cgi", "aspx", "war", "bat",
                    "c", "cc", "cpp", "cs", "go", "lua", "perl", "pl",
                    "py", "rb", "vb", "vbs", "vba", "h", "jar", "properties",
                    "config", "class"]


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
                print("func_retry: {} failed".format(fn.__name__))

        return inner

    return deco_retry


# noinspection DuplicatedCode
class EipTools(object):
    def __init__(self, *args, **kwargs):
        super(EipTools, self).__init__(*args, **kwargs)

    @classmethod
    def output_txt(cls, eip_info_list):
        with open(GlobalConfig.scan_obs_result, "w", encoding="utf-8") as f:
            for content in eip_info_list:
                f.write(content)
                f.write("\n")

    @classmethod
    def parse_input_args(cls):
        par = argparse.ArgumentParser()
        par.add_argument("-config_path", "--config_path", help="The config path of object", required=False)
        args = par.parse_args()
        return args

    @staticmethod
    def load_yaml(file_path, method="load"):
        """
        method: load_all/load
        """
        yaml_load_method = getattr(yaml, method)
        with open(file_path, "r", encoding="utf-8") as file:
            content = yaml_load_method(file, Loader=yaml.FullLoader)
        return content

    @classmethod
    def check_config_data(cls, config_list):
        for config_temp in config_list:
            if config_temp.get("account") is None:
                raise Exception("Account is invalid")
            if config_temp.get("ak") is None:
                raise Exception("Ak is invalid")
            if config_temp.get("sk") is None:
                raise Exception("Sk is invalid")

    @classmethod
    def get_bucket_acl(cls, obs_client, bucket_name):
        if not isinstance(obs_client, ObsClient):
            raise Exception("obs_client must be instantiated")
        list_result = list()
        try:
            resp = obs_client.getBucketAcl(bucket_name)
            if resp.status < 300:
                for grant in resp.body.grants:
                    list_result.append(dict(grant))
            else:
                print('get_bucket_acl:errorCode:', resp.errorCode)
                print('get_bucket_acl:errorMessage:', resp.errorMessage)
        except Exception as e:
            print("get_bucket_acl:{}, traceback:{}".format(e, traceback.format_exc()))
        return list_result

    @classmethod
    def get_bucket_obj(cls, obs_client, bucket_name):
        if not isinstance(obs_client, ObsClient):
            raise Exception("obs_client must be instantiated")
        list_result = list()
        try:
            resp = obs_client.listObjects(bucket_name, max_keys=100000)
            if resp.status < 300:
                for content in resp.body.contents:
                    list_result.append(content)
            else:
                print('get_bucket_obj:errorCode:', resp.errorCode)
                print('get_bucket_obj:errorMessage:', resp.errorMessage)
        except Exception as e:
            print("get_bucket_obj:{}, traceback:{}".format(e, traceback.format_exc()))
        return list_result

    @classmethod
    def check_bucket_info(cls, obs_client, bucket_name, account):
        list_result = list()
        acl_list = cls.get_bucket_acl(obs_client, bucket_name)
        is_anonymous = False
        for acl_info in acl_list:
            group_info = acl_info["grantee"].get("group")
            if group_info is not None and acl_info["grantee"]["group"] == "Everyone":
                is_anonymous = True
                break
        if is_anonymous:
            bucket_info_list = cls.get_bucket_obj(obs_client, bucket_name)
            for bucket_info in bucket_info_list:
                file_name = bucket_info["key"]
                file_name_list = file_name.rsplit(sep=".", maxsplit=1)
                if len(file_name_list) >= 2:
                    if file_name_list[-1] in GlobalConfig.file_postfix:
                        file_temp = "{}:{}/{}".format(account, bucket_name, file_name)
                        print("collect:{}".format(file_temp))
                        list_result.append(file_temp)
        return list_result

    @classmethod
    def get_bucket_list(cls, obs_client):
        if not isinstance(obs_client, ObsClient):
            raise Exception("obs_client must be instantiated")
        list_bucket = list()
        try:
            resp = obs_client.listBuckets()
            if resp.status < 300:
                for bucket in resp.body.buckets:
                    if bucket['bucket_type'] == "OBJECT":
                        list_bucket.append(dict(bucket))
            else:
                print('get_bucket_list: errorCode:', resp.errorCode)
                print('get_bucket_list: errorMessage:', resp.errorMessage)
        except Exception as e:
            print("get_bucket_list:{}".format(e))
        return list_bucket

    @classmethod
    def get_all_bucket(cls, ak, sk, url):
        location_bucket = defaultdict(list)
        with ObsClientConn(ak, sk, url) as obs_client:
            list_bucket = cls.get_bucket_list(obs_client)
            for bucket_info in list_bucket:
                location_bucket[bucket_info["location"]].append(bucket_info["name"])
            return location_bucket


class ObsClientConn(object):
    def __init__(self, ak, sk, url, timeout=180):
        self.obs_client = ObsClient(access_key_id=ak, secret_access_key=sk, server=url, timeout=timeout)

    def __enter__(self):
        return self.obs_client

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.obs_client:
            self.obs_client.close()


# noinspection DuplicatedCode
def main():
    """
    1.获取所有的桶信息
    2.如果这个桶是匿名用户，则遍历所有的文件和文件夹，如果是后缀名是.结尾的，则添加到列表中
    3.输出到txt中
    """
    eip_tools = EipTools()
    input_args = eip_tools.parse_input_args()
    print("##################1.start to parse params #############")
    if not input_args.config_path:
        config_path = GlobalConfig.config_path
    else:
        config_path = input_args.config_path
    config_list = eip_tools.load_yaml(config_path)
    eip_tools.check_config_data(config_list)
    print("############2.start to collect and output to txt######")
    result_list = list()
    for config_item in config_list:
        ak = config_item["ak"]
        sk = config_item["sk"]
        account = config_item["account"]
        location_bucket = eip_tools.get_all_bucket(ak, sk, GlobalConfig.url)
        for location, bucket_name_list in location_bucket.items():
            url = "https://obs.{}.myhuaweicloud.com".format(location)
            with ObsClientConn(ak, sk, url) as obs_client:
                for bucket_name in bucket_name_list:
                    ret_temp = eip_tools.check_bucket_info(obs_client, bucket_name, account)
                    result_list.extend(ret_temp or [])
    eip_tools.output_txt(result_list)
    print("##################3.finish################")


if __name__ == "__main__":
    main()
