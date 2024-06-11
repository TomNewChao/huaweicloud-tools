# -*- coding: utf-8 -*-
# @Time    : 2024/5/30 16:21
# @Author  : Tom_zc
# @FileName: scan_etherpad.py
# @Software: PyCharm

import click
import traceback
import threading
import yaml
import smtplib
import time

from functools import wraps
from concurrent.futures import ThreadPoolExecutor, wait
from email.mime.text import MIMEText
from email.header import Header

from huaweicloudsdkcore.exceptions.exceptions import ClientRequestException
from py_etherpad import EtherpadLiteClient
from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkmoderation.v3.region.moderation_region import ModerationRegion
from huaweicloudsdkcore.exceptions import exceptions
from huaweicloudsdkmoderation.v3 import ModerationClient, TextDetectionReq, RunTextModerationRequest, \
    TextDetectionDataReq

yaml_fileds = ["huawei_ak", "huawei_sk", "etherpad_url", "etherpad_token",
               "mta_sender", "mta_receivers", "mta_ip", "mta_port",
               "mta_username", "mta_password", "mta_subject"]


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


class CloudClient:

    def __init__(self, ak, sk):
        credentials = BasicCredentials(ak, sk)
        self._client = ModerationClient.new_builder() \
            .with_credentials(credentials) \
            .with_region(ModerationRegion.value_of("cn-north-4")) \
            .build()

    @property
    def client(self):
        return self._client


class ScanResult:
    _lock = threading.Lock()
    _scan_result = dict()

    @classmethod
    def update_result(cls, dict_data):
        if not isinstance(dict_data, dict):
            raise RuntimeError("update_result must be dict")
        with cls._lock:
            cls._scan_result.update(dict_data)

    @property
    def result(self):
        return self._scan_result


def scan_text(client, text):
    try:
        request = RunTextModerationRequest()
        databody = TextDetectionDataReq(
            language="zh",
            text=text
        )
        request.body = TextDetectionReq(
            biz_type="scan_etherpad",
            data=databody
        )
        response = client.client.run_text_moderation(request)
        if response.result.suggestion == "pass":
            return False, str()
        return True, "reason:{},detail:{}".format(response.result.label, str(response.result.details))
    except exceptions.ClientRequestException as e:
        print("e:{}, traceback:{}".format(e, traceback.format_exc()))
        return True, e


@func_retry()
def work_on_thread(pad, config_obj):
    pad_content = pad
    last_content = set()
    client = CloudClient(config_obj["huawei_ak"], config_obj["huawei_sk"])
    elc = EtherpadLiteClient(apiKey=config_obj["etherpad_token"], baseUrl=config_obj["etherpad_url"])
    if config_obj.get("scan_version_history"):
        revisions = elc.getRevisionsCount(pad)
        print("find the pad:{} and revision count is:{}".format(pad, revisions))
        for i in range(revisions["revisions"] + 1):
            content = elc.getText(pad, i)
            line_sets = set(content["text"].split("\n"))
            added_conent = line_sets - last_content
            pad_content += "\n".join(list(added_conent))
            last_content = last_content.union(line_sets)
    else:
        content = elc.getText(pad)
        pad_content = content["text"]
    pad_content_length = len(pad_content)
    if pad_content_length <= 1500:
        is_err, result = scan_text(client, pad_content)
        if is_err:
            scan_result = ScanResult()
            scan_result.update_result({pad: result})
            print("find the result is:{}".format(pad, result))
            return False, pad, result
    else:
        print("find the pad: {} and the content length gt 1500 and is:{}".format(pad, pad_content_length))
        for i in range(0, pad_content_length, 1500):
            start_index = i
            end_index = 1500 + i
            if end_index > pad_content_length:
                end_index = pad_content_length
            is_err, result = scan_text(client, pad_content[start_index: end_index])
            if is_err:
                scan_result = ScanResult()
                scan_result.update_result({pad: result})
                print("find the result is:{}".format(pad, result))
                return False, pad, result

    return True, pad, str()


def scan_etherpad(config_obj):
    executor = ThreadPoolExecutor(max_workers=20)
    elc = EtherpadLiteClient(apiKey=config_obj["etherpad_token"], baseUrl=config_obj["etherpad_url"])
    all_pads = elc.listAllPads()
    print("find the pads count:{}".format(len(all_pads["padIDs"])))
    all_tasks = [executor.submit(work_on_thread, pad, config_obj) for pad in all_pads["padIDs"]]
    # all_tasks = [executor.submit(work_on_thread, pad, config_obj) for pad in ["Debian_team_sync_note"]]
    wait(all_tasks)
    for task in all_tasks:
        print("result is {}".format(task.result()))


def generate_text():
    scan_result = ScanResult()
    text = str()
    for pad, result in scan_result.result.items():
        text += "{}:{}\n".format(pad, result)
        if isinstance(result, ClientRequestException):
            print("find the error:{}".format(pad))
            continue
        if result.split(",")[0].split(":")[1] != "ad":
            print("pad:{}, result:{}".format(pad, result))
    return text


def send_email(config_obj):
    text = generate_text()
    message = MIMEText(text, 'plain', 'utf-8')
    message['Subject'] = Header(config_obj["mta_subject"], 'utf-8')
    message['To'] = config_obj["mta_receivers"]
    smtp_obj = smtplib.SMTP(config_obj["mta_ip"], config_obj["mta_port"])
    smtp_obj.login(config_obj["mta_username"], config_obj["mta_password"])
    smtp_obj.sendmail(config_obj["mta_sender"], config_obj["mta_receivers"], message.as_string())


def parse_config(config_path):
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def check_config(config_obj):
    fields = list(set(yaml_fileds) - set(config_obj.keys()))
    if fields:
        raise RuntimeError("lack the fields of:{}".format(",".join(fields)))


@click.command()
@click.option("--path", default="./config.yaml", help='The path of script config')
def main(path):
    config_obj = parse_config(path)
    check_config(config_obj)
    scan_etherpad(config_obj)
    send_email(config_obj)


if __name__ == '__main__':
    main()
