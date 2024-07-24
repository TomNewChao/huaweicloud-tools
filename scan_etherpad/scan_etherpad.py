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

from dataclasses import dataclass
from urllib.parse import urlsplit
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, wait
from email.mime.text import MIMEText
from email.header import Header

from py_etherpad import EtherpadLiteClient
from huaweicloudsdkcore.http.http_config import HttpConfig
from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkmoderation.v3.region.moderation_region import ModerationRegion
from huaweicloudsdkcore.exceptions import exceptions
from huaweicloudsdkmoderation.v3 import ModerationClient, TextDetectionReq, RunTextModerationRequest, \
    TextDetectionDataReq

_yaml_fields = ["huawei_ak", "huawei_sk", "community_etherpad",
                "mta_sender", "mta_receivers", "mta_ip", "mta_port",
                "mta_username", "mta_password", "mta_subject_sensor",
                "mta_subject_count", "scan_version_history"]

_notify_div_template = textwrap.dedent("""
    <div>
    <p>亲:</p>
    <p>这是osInfra扫描中心，etherpad敏感信息扫描结果如下图所示，共发现疑似包含敏感信息{}条，请及时处理：</p>
    <div class="table-detail">{}</div>
    </div>
""").strip()

_notify_count_template = textwrap.dedent("""
    <div>
    <p>亲:</p>
    <p>这是osInfra扫描中心，etherpad数据统计结果如下图所示：</p>
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


@dataclass
class CommunityEtherpad:
    etherpad_url: str
    etherpad_token: str
    community: str
    huawei_ak: str
    huawei_sk: str
    scan_version_history: str


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
        config = HttpConfig.get_default_config()
        config.timeout = (1800, 1800)
        credentials = BasicCredentials(ak, sk)
        self._client = ModerationClient.new_builder() \
            .with_credentials(credentials) \
            .with_region(ModerationRegion.value_of("cn-north-4")) \
            .with_http_config(config).build()

    @property
    def client(self):
        return self._client


class ScanResult:
    _lock = threading.Lock()
    _scan_result = list()

    @classmethod
    def update_result(cls, list_data):
        if not isinstance(list_data, list):
            raise RuntimeError("update_result must be list")
        with cls._lock:
            cls._scan_result.extend(list_data)

    @property
    def result(self):
        return self._scan_result


class CountResult:
    _lock = threading.Lock()
    _count_result = list()

    @classmethod
    def update_result(cls, list_data):
        if not isinstance(list_data, list):
            raise RuntimeError("[CountResult] update_result must be list")
        with cls._lock:
            cls._count_result.extend(list_data)

    @property
    def result(self):
        return self._count_result


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
    finally:
        # Dealing with frequency limiting
        time.sleep(0.5)


def get_reject_describe(pad, community_etherpad, result):
    reject_details = list()
    url_obj = urlsplit(community_etherpad.etherpad_url)
    domain = url_obj.scheme + "://" + url_obj.netloc
    link = url_obj.scheme + "://" + url_obj.netloc + "/p/" + pad
    for detail in result:
        confidence = round(detail.confidence, 3)
        label = detail.label
        if label.lower() == "ad" and confidence < 0.9:
            continue
        domain_html = "<a href='{0}'>{1}</a>".format(domain, community_etherpad.community)
        data = {
            "community": domain_html,
            "pad_name": "<a href='{0}'>{1}</a>".format(link, pad),
            "reason": label,
            "confidence": confidence,
            "detail": ""
        }
        if detail.segments:
            data["detail"] = ".".join(
                ["words:" + i.segment + ";location:" + ",".join([str(j) for j in i.position]) for i in detail.segments])
        reject_details.append(data)
    return reject_details


def work(elc, cc, pad, community_etherpad, empty_pad_name):
    pad_content = pad
    last_content = set()
    if community_etherpad.scan_version_history:
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
        if (pad_content.strip().startswith("Welcome to Etherpad") and pad_content.strip().endswith("etherpad.org")) or (
                len(pad_content.strip()) == 0):
            empty_pad_name.append(pad)
        pad_content = pad + content["text"]
    pad_content_length = len(pad_content)
    if pad_content_length <= 1500:
        is_err, result = scan_text(cc, pad_content)
        if is_err:
            if result is None:
                print("request the scan text failed:{}".format(pad))
                return list()
            print("find the result is:{}".format(pad, result))
            return get_reject_describe(pad, community_etherpad, result)
    else:
        print("find the pad: {} and the content length gt 1500 and is:{}".format(pad, pad_content_length))
        for i in range(0, pad_content_length, 1500):
            start_index = i
            end_index = 1500 + i
            if end_index > pad_content_length:
                end_index = pad_content_length
            is_err, result = scan_text(cc, pad_content[start_index: end_index])
            if is_err:
                if result is None:
                    print("request the scan text failed:{}".format(pad))
                    continue
                print("find the result is:{}".format(pad, result))
                return get_reject_describe(pad, community_etherpad, result)
    return list()


@func_retry()
def scan_single_community(community_etherpad):
    if not isinstance(community_etherpad, CommunityEtherpad):
        raise RuntimeError("community_etherpad must be CommunityEtherpad")
    cc = CloudClient(community_etherpad.huawei_ak, community_etherpad.huawei_sk)
    elc = EtherpadLiteClient(apiKey=community_etherpad.etherpad_token,
                             baseUrl=community_etherpad.etherpad_url)
    all_pads = elc.listAllPads()
    print("find the pads count:{}".format(len(all_pads["padIDs"])))
    scan_list = list()
    empty_pad_name = list()
    for pad in all_pads["padIDs"]:
        scan_single_list = work(elc, cc, pad, community_etherpad, empty_pad_name)
        if scan_single_list:
            scan_list.extend(scan_single_list)
    scan_result = ScanResult()
    scan_result.update_result(scan_list)
    count_result = CountResult()
    count_result.update_result([{
        "community": community_etherpad.community,
        "total_pad_count": len(all_pads["padIDs"]),
        "empty_pad_count": len(empty_pad_name),
        "empty_pad_name": ",".join(empty_pad_name)
    }])


def scan_etherpad(config_obj):
    executor = ThreadPoolExecutor(max_workers=20)
    all_tasks = [executor.submit(scan_single_community, CommunityEtherpad(
        etherpad_url=community["etherpad_url"],
        etherpad_token=community["etherpad_token"],
        community=community["community"],
        huawei_ak=config_obj["huawei_ak"],
        huawei_sk=config_obj["huawei_sk"],
        scan_version_history=config_obj["scan_version_history"],
    )) for community in config_obj["community_etherpad"]]
    wait(all_tasks)


# noinspection PyTypeChecker,SpellCheckingInspection
def generate_sensitive_html():
    cleaned_info = ScanResult().result
    cleaned_info = sorted(cleaned_info, key=lambda x: (x["community"], x["confidence"]), reverse=True)
    pd.set_option('display.width', 800)
    pd.set_option('display.max_colwidth', 150)
    pd.set_option('colheader_justify', 'center')
    pd.options.display.html.border = 2
    df = pd.DataFrame.from_dict(cleaned_info)
    format_dict = {'confidence': '{0:.3f}'}
    df_style = df.style.hide_index().format(format_dict)
    html = df_style.render()
    content = _notify_div_template.format(len(cleaned_info), html)
    template_content = _html_template.replace(r"{{template}}", content)
    return template_content


# noinspection PyTypeChecker
def generate_count_html():
    cleaned_info = CountResult().result
    pd.set_option('display.width', 400)
    pd.set_option('display.max_colwidth', 200)
    pd.set_option('colheader_justify', 'center')
    pd.options.display.html.border = 2
    df = pd.DataFrame.from_dict(cleaned_info)
    df_style = df.style.hide_index()
    html = df_style.render()
    content = _notify_count_template.format(html)
    template_content = _html_template.replace(r"{{template}}", content)
    return template_content


def send_email(config_obj):
    print("----------start to send email---------")
    smtp_obj = smtplib.SMTP(config_obj["mta_ip"], config_obj["mta_port"])
    smtp_obj.login(config_obj["mta_username"], config_obj["mta_password"])

    text = generate_sensitive_html()
    message = MIMEText(text, "html", 'utf-8')
    message['Subject'] = Header(config_obj["mta_subject_sensor"], 'utf-8')
    message['To'] = config_obj["mta_receivers"]
    smtp_obj.sendmail(config_obj["mta_sender"], config_obj["mta_receivers"], message.as_string())

    text = generate_count_html()
    message = MIMEText(text, "html", 'utf-8')
    message['Subject'] = Header(config_obj["mta_subject_count"], 'utf-8')
    message['To'] = config_obj["mta_receivers"]
    smtp_obj.sendmail(config_obj["mta_sender"], config_obj["mta_receivers"], message.as_string())


def _parse_config(config_path):
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _check_config(config_obj):
    fields = list(set(_yaml_fields) - set(config_obj.keys()))
    if fields:
        raise RuntimeError("lack the fields of:{}".format(",".join(fields)))
    for community in config_obj["community_etherpad"]:
        if community.get("etherpad_url") is None:
            raise RuntimeError("lack the fields of etherpad_url.")
        if community.get("etherpad_token") is None:
            raise RuntimeError("lack the fields of etherpad_token.")
        if community.get("community") is None:
            raise RuntimeError("lack the fields of community.")


@click.command()
@click.option("--path", default="./config.yaml", help='The path of script config')
def main(path):
    config_path = os.getenv("CONFIG_PATH")
    if not config_path:
        config_path = path
    config_obj = _parse_config(config_path)
    _check_config(config_obj)
    scan_etherpad(config_obj)
    send_email(config_obj)


if __name__ == '__main__':
    main()
