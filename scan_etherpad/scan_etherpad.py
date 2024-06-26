# -*- coding: utf-8 -*-
# @Time    : 2024/5/30 16:21
# @Author  : Tom_zc
# @FileName: scan_etherpad.py
# @Software: PyCharm
import os
import textwrap
import traceback

import click
import threading
import yaml
import smtplib
import time
import pandas as pd

from urllib.parse import urlsplit
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, wait
from email.mime.text import MIMEText
from email.header import Header

from py_etherpad import EtherpadLiteClient
from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkmoderation.v3.region.moderation_region import ModerationRegion
from huaweicloudsdkcore.exceptions import exceptions
from huaweicloudsdkmoderation.v3 import ModerationClient, TextDetectionReq, RunTextModerationRequest, \
    TextDetectionDataReq

_yaml_fields = ["huawei_ak", "huawei_sk", "etherpad_url", "etherpad_token",
                "mta_sender", "mta_receivers", "mta_ip", "mta_port",
                "mta_username", "mta_password", "mta_subject", "community"]

_notify_div_template = textwrap.dedent("""
    <div>
    <p>亲:</p>
    <p>这是osInfra扫描中心，扫描地址：{}，etherpad敏感信息扫描结果如下图所示，请及时处理：</p>
    <div class="table-detail">{}</div>
    </div>
""").strip()

_html_template = textwrap.dedent("""
<html>
<meta http-equiv="Content-Type" content="text/html;charset=UTF-8"/>
<head>
    <title>MindSpore</title>
    <style>

        table {
            border-collapse: collapse
        }

        th, td {
            border: 1px solid #000
        }

        .table-detail {
            left: 20px;
            bottom: 20px
        }
    </style>
</head>
<body>
{{template}}
</body>
</html>
""").strip()


def func_retry(tries=5, delay=10):
    def deco_retry(fn):
        @wraps(fn)
        def inner(*args, **kwargs):
            for i in range(tries):
                try:
                    return fn(*args, **kwargs)
                except Exception as e:
                    print("e:{},traceback:{}".format(e, traceback.format_exc()))
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
    _scan_result = list()

    @classmethod
    def update_result(cls, dict_data):
        if not isinstance(dict_data, list):
            raise RuntimeError("update_result must be list")
        with cls._lock:
            cls._scan_result.extend(dict_data)

    @property
    def result(self):
        return self._scan_result


def scan_text(client, text):
    try:
        request = RunTextModerationRequest()
        body = TextDetectionDataReq(
            language="zh",
            text=text
        )
        request.body = TextDetectionReq(
            biz_type="scan_etherpad",
            data=body
        )
        response = client.client.run_text_moderation(request)
        if response.result.suggestion == "pass":
            return False, None
        return True, response.result.details
    except exceptions.ClientRequestException as e:
        print("e:{}".format(e))
        return True, None


def get_reject_describe(pad, config_obj, result):
    reject_details = list()
    url_obj = urlsplit(config_obj["etherpad_url"])
    link = url_obj.scheme + "://" + url_obj.netloc + "/p/" + pad
    for detail in result:
        data = {
            "pad_name": "<a href='{0}'>{1}</a>".format(link, pad),
            "reason": detail.label,
            "confidence": round(detail.confidence, 3),
            "detail": ""
        }
        if detail.segments:
            data["detail"] = ".".join(
                ["words:" + i.segment + ";location:" + ",".join([str(j) for j in i.position]) for i in detail.segments])
        reject_details.append(data)
    return reject_details


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
            added_content = line_sets - last_content
            pad_content += "\n".join(list(added_content))
            last_content = last_content.union(line_sets)
    else:
        content = elc.getText(pad)
        pad_content = content["text"]
    pad_content_length = len(pad_content)
    if pad_content_length <= 1500:
        is_err, result = scan_text(client, pad_content)
        if is_err:
            if result is None:
                print("request the scan text failed:{}".format(pad))
                return False
            scan_result = ScanResult()
            scan_result.update_result(get_reject_describe(pad, config_obj, result))
            print("find the result is:{}".format(pad, result))
            return False
    else:
        print("find the pad: {} and the content length gt 1500 and is:{}".format(pad, pad_content_length))
        for i in range(0, pad_content_length, 1500):
            start_index = i
            end_index = 1500 + i
            if end_index > pad_content_length:
                end_index = pad_content_length
            is_err, result = scan_text(client, pad_content[start_index: end_index])
            if is_err:
                if result is None:
                    print("request the scan text failed:{}".format(pad))
                    continue
                scan_result = ScanResult()
                scan_result.update_result(get_reject_describe(pad, config_obj, result))
                print("find the result is:{}".format(pad, result))
                return False

    return True


def scan_etherpad(config_obj):
    executor = ThreadPoolExecutor(max_workers=20)
    elc = EtherpadLiteClient(apiKey=config_obj["etherpad_token"], baseUrl=config_obj["etherpad_url"])
    all_pads = elc.listAllPads()
    print("find the pads count:{}".format(len(all_pads["padIDs"])))
    # work_on_thread("12345", config_obj)
    all_tasks = [executor.submit(work_on_thread, pad, config_obj) for pad in all_pads["padIDs"]]
    wait(all_tasks)


# noinspection PyTypeChecker,SpellCheckingInspection
def generate_html(config_obj):
    cleaned_info = ScanResult().result
    pd.set_option('display.width', 800)
    pd.set_option('display.max_colwidth', 150)
    pd.set_option('colheader_justify', 'center')
    pd.options.display.html.border = 2
    df = pd.DataFrame.from_dict(cleaned_info)
    format_dict = {'confidence': '{0:.3f}'}
    df_style = df.style.hide_index().format(format_dict)
    html = df_style.render()
    url_obj = urlsplit(config_obj["etherpad_url"])
    domain = url_obj.scheme + "://" + url_obj.netloc
    domain_html = "<a href='{0}'>{1}</a>".format(domain, config_obj["community"])
    content = _notify_div_template.format(domain_html, html)
    template_content = _html_template.replace(r"{{template}}", content)
    return template_content


def send_email(config_obj):
    text = generate_html(config_obj)
    message = MIMEText(text, "html", 'utf-8')
    message['Subject'] = Header(config_obj["mta_subject"], 'utf-8')
    message['To'] = config_obj["mta_receivers"]
    smtp_obj = smtplib.SMTP(config_obj["mta_ip"], config_obj["mta_port"])
    smtp_obj.login(config_obj["mta_username"], config_obj["mta_password"])
    smtp_obj.sendmail(config_obj["mta_sender"], config_obj["mta_receivers"], message.as_string())


def _parse_config(config_path):
    if not os.path.exists(config_path):
        config_path = os.getenv("config_path")
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _check_config(config_obj):
    fields = list(set(_yaml_fields) - set(config_obj.keys()))
    if fields:
        raise RuntimeError("lack the fields of:{}".format(",".join(fields)))


@click.command()
@click.option("--path", default="./config.yaml", help='The path of script config')
def main(path):
    config_obj = _parse_config(path)
    _check_config(config_obj)
    scan_etherpad(config_obj)
    send_email(config_obj)


if __name__ == '__main__':
    main()
