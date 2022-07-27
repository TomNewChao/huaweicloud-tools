# -*- coding: utf-8 -*-
# @Time    : 2022/6/8 17:30
# @Author  : Tom_zc
# @FileName: scan_obs.py
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
    scan_obs_sensitive_file = os.path.join(base_path, "scan_obs_sensitive_file.csv")
    scan_obs_anonymous_bucket = os.path.join(base_path, "scan_obs_anonymous_bucket.csv")
    scan_obs_anonymous_data = os.path.join(base_path, "scan_obs_anonymous_data.csv")
    config_path = os.path.join(base_path, "scan_obs.yaml")

    url = "obs.cn-north-4.myhuaweicloud.com"
    base_url = "https://obs.{}.myhuaweicloud.com"


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
    _ex = extractor()

    def __init__(self, *args, **kwargs):
        super(EipTools, self).__init__(*args, **kwargs)

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
        if config_obj.get("check_bucket") is None:
            raise Exception("check_bucket is invalid")
        if config_obj.get("check_sensitive_file") is None:
            raise Exception("check_sensitive_file is invalid")
        if config_obj.get("check_sensitive_content") is None:
            raise Exception("check_sensitive_content is invalid")
        if config_obj.get("sensitive_file_suffix") is None:
            raise Exception("sensitive_file_suffix is invalid")
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
    def get_bucket_policy(cls, obs_client, bucket_name):
        if not isinstance(obs_client, ObsClient):
            raise Exception("obs_client must be instantiated")
        try:
            resp = obs_client.getBucketPolicy(bucket_name)
            if resp.status < 300:
                return resp.body.policyJSON
            elif resp.errorCode == "NoSuchBucketPolicy":
                return None
            else:
                print('get_bucket_bucket:errorCode:', resp.errorCode)
                print('get_bucket_bucket:errorMessage:', resp.errorMessage)
        except Exception as e:
            print("get_bucket_acl:{}, traceback:{}".format(e, traceback.format_exc()))
        return None

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

    # noinspection PyBroadException
    @classmethod
    def download_obs_data(cls, obs_client, bucket_name, obs_key):
        """download obs data"""
        content = str()
        resp = obs_client.getObject(bucket_name, obs_key, loadStreamInMemory=False)
        if resp.status < 300:
            try:
                while True:
                    chunk = resp.body.response.read(65536)
                    if not chunk:
                        break
                    content = "{}{}".format(content, chunk.decode("utf-8"))
            except Exception:
                pass
            resp.body.response.close()
        elif resp.errorCode == "NoSuchKey":
            print("Key:{} is not exist, need to create".format(obs_key))
        else:
            print('errorCode:', resp.errorCode)
            print('errorMessage:', resp.errorMessage)
        return content

    # noinspection PyBroadException
    @classmethod
    def get_sensitive_data(cls, content):
        sensitive_dict_data = dict()
        if not content:
            return sensitive_dict_data
        try:
            name = cls._ex.extract_name(content)
            if name:
                sensitive_dict_data["name"] = name
        except Exception:
            pass
        sensitive_email = cls._ex.extract_email(content)
        sensitive_phone = cls._ex.extract_cellphone(content, nation='CHN')
        if sensitive_email:
            sensitive_dict_data["email"] = sensitive_email
        if sensitive_phone:
            sensitive_dict_data["phone_number"] = sensitive_phone
        return sensitive_dict_data

    @classmethod
    def check_bucket_info(cls, config_obj, obs_client, bucket_name, account):
        list_anonymous_file, list_anonymous_bucket, list_anonymous_data = list(), list(), list()
        is_anonymous = False
        if not config_obj["check_bucket"] and not config_obj["check_sensitive_file"] and not config_obj["check_sensitive_content"]:
            return list_anonymous_file, list_anonymous_bucket, list_anonymous_data
        # first to judge bucket policy
        policy_content = cls.get_bucket_policy(obs_client, bucket_name)
        if policy_content:
            policy_obj = json.loads(policy_content)
            for statement_info in policy_obj["Statement"]:
                if statement_info.get("Principal") is not None and r"*" in statement_info["Principal"]["ID"]:
                    is_anonymous = True
                    break
        # second to judge bucket acl
        if not is_anonymous:
            acl_list = cls.get_bucket_acl(obs_client, bucket_name)
            for acl_info in acl_list:
                group_info = acl_info["grantee"].get("group")
                if group_info is not None and acl_info["grantee"]["group"] == "Everyone":
                    is_anonymous = True
                    break
        if is_anonymous:
            anonymous_bucket = [account, bucket_name]
            print("collect anonymous bucket:{}".format(anonymous_bucket))
            if config_obj["check_bucket"]:
                list_anonymous_bucket.append(anonymous_bucket)
            bucket_info_list = cls.get_bucket_obj(obs_client, bucket_name)
            for bucket_info in bucket_info_list:
                file_name = bucket_info["key"]
                file_name_list = file_name.rsplit(sep=".", maxsplit=1)
                if len(file_name_list) >= 2:
                    if file_name_list[-1] in config_obj["sensitive_file_suffix"]:
                        file_temp = [account, bucket_name, file_name]
                        print("collect sensitive file:{}".format(file_temp))
                        if config_obj["check_sensitive_file"]:
                            list_anonymous_file.append(file_temp)
                        if config_obj["check_sensitive_content"]:
                            content = cls.download_obs_data(obs_client, bucket_name, file_name)
                            sensitive_data = cls.get_sensitive_data(content)
                            if sensitive_data:
                                data_temp = [account, bucket_name, file_name, str(sensitive_data)]
                                print("collect sensitive data:{}".format(data_temp))
                                list_anonymous_data.append(data_temp)
        return list_anonymous_file, list_anonymous_bucket, list_anonymous_data

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
    config_obj = eip_tools.load_yaml(config_path)
    eip_tools.check_config_data(config_obj)
    print("############2.start to collect and output to txt######")
    result_list, list_anonymous_bucket, list_anonymous_data = list(), list(), list()
    for config_item in config_obj["account_info"]:
        ak = config_item["ak"]
        sk = config_item["sk"]
        account = config_item["account"]
        location_bucket = eip_tools.get_all_bucket(ak, sk, GlobalConfig.url)
        for location, bucket_name_list in location_bucket.items():
            url = GlobalConfig.base_url.format(location)
            with ObsClientConn(ak, sk, url) as obs_client:
                for bucket_name in bucket_name_list:
                    ret_temp, list_anonymous_bucket_temp, list_anonymous_data_temp = eip_tools.check_bucket_info(
                        config_obj, obs_client,
                        bucket_name, account)
                    result_list.extend(ret_temp or [])
                    list_anonymous_bucket.extend(list_anonymous_bucket_temp or [])
                    list_anonymous_data.extend(list_anonymous_data_temp or [])
    eip_tools.output_txt(GlobalConfig.scan_obs_sensitive_file, result_list)
    eip_tools.output_txt(GlobalConfig.scan_obs_anonymous_bucket, list_anonymous_bucket)
    eip_tools.output_txt(GlobalConfig.scan_obs_anonymous_data, list_anonymous_data)
    print("##################3.finish################")


if __name__ == "__main__":
    main()
