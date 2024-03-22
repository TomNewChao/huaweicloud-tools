# -*- coding: utf-8 -*-
# @Time    : 2024/3/22 14:20
# @Author  : Tom_zc
# @FileName: scan_obs_public_file.py
# @Software: PyCharm
import json
import os
import argparse
import time
import yaml
import traceback
import csv
from collections import defaultdict
from functools import wraps
from obs.client import ObsClient
from cocoNLP.extractor import extractor


# noinspection DuplicatedCode
class GlobalConfig(object):
    base_path = os.path.dirname(__file__)
    config_path = os.path.join(base_path, "scan_obs_public_file.yaml")
    url = "obs.cn-north-4.myhuaweicloud.com"
    base_url = "https://obs.{}.myhuaweicloud.com"
    anonymous_user = "Everyone"


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
class ObsTools(object):
    _ex = extractor()

    def __init__(self, *args, **kwargs):
        super(ObsTools, self).__init__(*args, **kwargs)

    @classmethod
    def output_txt(cls, path, eip_info_list):
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            writer = csv.writer(f)
            writer.writerows(eip_info_list)

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
    def check_config_data(cls, config_obj):
        if isinstance(config_obj.get("account_info"), dict):
            raise Exception("account_info")
        for config_temp in config_obj["account_info"]:
            if config_temp.get("account") is None:
                raise Exception("Account is invalid")
            if config_temp.get("ak") is None:
                raise Exception("Ak is invalid")
            if config_temp.get("sk") is None:
                raise Exception("Sk is invalid")

    @classmethod
    def get_bucket_obj(cls, obs_client, bucket_name, prefix=None):
        if not isinstance(obs_client, ObsClient):
            raise Exception("obs_client must be instantiated")
        list_result = list()
        try:
            resp = obs_client.listObjects(bucket_name, prefix=prefix, max_keys=100000)
            if resp.status < 300:
                for content in resp.body.contents:
                    list_result.append(content)
            else:
                logger.info('get_bucket_obj:errorCode:', resp.errorCode)
                logger.info('get_bucket_obj:errorMessage:', resp.errorMessage)
        except Exception as e:
            logger.info("get_bucket_obj:{}, traceback:{}".format(e, traceback.format_exc()))
        return list_result

    # noinspection PyBroadException
    @classmethod
    def get_obs_data(cls, obs_client, bucket_name, obs_key):
        """download obs data"""
        # bucket_name = "obs-for-openeuler-developer"
        # obs_key = "soft-tools/sysdiag-full-5.0.75.3-2024.03.21.1.exe"
        resp = obs_client.getObjectAcl(bucket_name, obs_key)
        if resp.status < 300:
            grantees = [i["grantee"] for i in resp.body["grants"]]
            anonymous = list(map(lambda x: x.get("group"), grantees))
            print("find the file:{}/{} is exist the anonymous user:{}".format(bucket_name, obs_key,
                                                                              GlobalConfig.anonymous_user in anonymous))
            return GlobalConfig.anonymous_user in anonymous
        elif resp.errorCode == "NoSuchKey":
            print("Key:{} is not exist, need to create".format(obs_key))
            return False
        else:
            print('errorCode:{}, errorMessage:{}'.format(resp.errorCode, resp.errorMessage))
            return True

    @classmethod
    def check_anonymous_file(cls, obs_client, bucket_name, account):
        file_list = list()
        bucket_info_list = cls.get_bucket_obj(obs_client, bucket_name)
        for bucket_info in bucket_info_list:
            file_name = bucket_info["key"]
            if cls.get_obs_data(obs_client, bucket_name, file_name):
                file_list.append("{}:{}:{}".format(account, bucket_name, file_name))
        return file_list

    @classmethod
    def __get_bucket_list(cls, obs_client):
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
            list_bucket = cls.__get_bucket_list(obs_client)
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
    obs_tools = ObsTools()
    input_args = obs_tools.parse_input_args()
    print("##################1.start to parse params #############")
    if not input_args.config_path:
        config_path = GlobalConfig.config_path
    else:
        config_path = input_args.config_path
    config_obj = obs_tools.load_yaml(config_path)
    obs_tools.check_config_data(config_obj)
    print("############2.start to collect######")
    all_anonymous_file_list = list()
    for config_item in config_obj["account_info"]:
        ak = config_item["ak"]
        sk = config_item["sk"]
        account = config_item["account"]
        location_bucket = obs_tools.get_all_bucket(ak, sk, GlobalConfig.url)
        for location, bucket_name_list in location_bucket.items():
            url = GlobalConfig.base_url.format(location)
            with ObsClientConn(ak, sk, url) as obs_client:
                for bucket_name in bucket_name_list:
                    anonymous_file_list = obs_tools.check_anonymous_file(obs_client, bucket_name, account)
                    all_anonymous_file_list.extend(anonymous_file_list)
    print("############3.start to output to txt######")
    with open("./result.txt", "w") as f:
        f.writelines(all_anonymous_file_list)
    print("##################4.finish################")


if __name__ == "__main__":
    """
    1.把指定账户的所有桶的文件拿出来
    2.获取文件的属性，如果文件的属性为公开，就打印出来
    """
    main()
