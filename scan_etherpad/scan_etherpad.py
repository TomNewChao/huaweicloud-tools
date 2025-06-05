# -*- coding: utf-8 -*-
# @Time    : 2024/5/30 16:21
# @Author  : Tom_zc
# @FileName: scan_etherpad.py
# @Software: PyCharm
import os
import sys
import textwrap
import traceback

import click
import threading
import yaml
import smtplib
import time
import logging
import requests
import pandas as pd

from dataclasses import dataclass
from urllib.parse import urlsplit
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, wait
from email.mime.text import MIMEText
from email.header import Header

from py_etherpad import EtherpadLiteClient


class Logger(object):
    level_relations = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'crit': logging.CRITICAL
    }

    def __init__(self, filename, level='info',
                 fmt='%(asctime)s - %(pathname)s[line:%(lineno)d] - %(levelname)s: %(message)s'):
        self.logger = logging.getLogger(filename)
        format_str = logging.Formatter(fmt)
        self.logger.setLevel(self.level_relations.get(level))
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(format_str)
        self.logger.addHandler(sh)


logger = Logger('scan_etherpad.log').logger

_yaml_fields = ["scan_url", "scan_token", "community_etherpad",
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
        
        td:nth-child(1), th:nth-child(1) { width: 100px; }
        td:nth-child(2), th:nth-child(2) { width: 100px; }
        td:nth-child(3), th:nth-child(3) { width: 100px; }
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
    scan_url: str
    scan_token: str
    scan_version_history: str


def func_retry(tries=5, delay=10):
    def deco_retry(fn):
        @wraps(fn)
        def inner(*args, **kwargs):
            for i in range(tries):
                try:
                    return fn(*args, **kwargs)
                except Exception as e:
                    logger.info("e:{},traceback:{}".format(e, traceback.format_exc()))
                    time.sleep(delay)
            else:
                logger.info("func_retry: {} failed".format(fn.__name__))

        return inner

    return deco_retry


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


class AuditClient:
    def __init__(self, url=None, token=None, audit_type="OFFICIAL_WEBSITE"):
        self._url = url
        self._token = token
        self._audit_type = audit_type

    def _post_audit(self, content):
        headers = {
            "Content-Type": "application/json",
            "Token": self._token,
        }
        data = {
            "type": self._audit_type,
            "text": content
        }
        resp = requests.post(url=self._url, headers=headers, json=data)
        if not str(resp.status_code).startswith("20"):
            raise Exception("request audit:{}, and error msg:{}".format(str(resp.status_code), resp.content.decode()))
        return resp.json()

    def check_content_ok(self, content):
        if self._url is None or self._token is None:
            logger.info("AuditClient the url and token is not config")
            return True, ""
        try:
            json_data = self._post_audit(content)
        except Exception as e:
            logger.info("check the content failed:{}".format(e))
            return False, str(e)
        if json_data["data"]["result"] == "pass":
            return  True, ""
        logger.info("check the content failed:{}".format(json_data))
        return False, json_data["data"]["exception"]


def get_reject_describe(pad, community_etherpad, result):
    reject_details = list()
    url_obj = urlsplit(community_etherpad.etherpad_url)
    domain = url_obj.scheme + "://" + url_obj.netloc
    link = url_obj.scheme + "://" + url_obj.netloc + "/p/" + pad
    domain_html = "<a href='{0}'>{1}</a>".format(domain, community_etherpad.community)
    data = {
        "community": domain_html,
        "pad_name": "<a href='{0}'>{1}</a>".format(link, pad),
        "reason": "block",
        "detail": result
    }
    reject_details.append(data)
    return reject_details


def work(elc, audit_client, pad, community_etherpad):
    empty_pad_name = list()
    pad_content = pad
    last_content = set()
    if community_etherpad.scan_version_history:
        revisions = elc.getRevisionsCount(pad)
        logger.info("find the pad:{} and revision count is:{}".format(pad, revisions))
        for i in range(revisions["revisions"] + 1):
            content = elc.getText(pad, i)
            line_sets = set(content["text"].split("\n"))
            added_content = line_sets - last_content
            pad_content += "\n".join(list(added_content))
            last_content = last_content.union(line_sets)
    else:
        content = elc.getText(pad)
        if (content["text"].strip().startswith("Welcome to Etherpad") and content["text"].strip().endswith(
                "etherpad.org")) or (
                len(content["text"].strip()) == 0):
            empty_pad_name.append(pad)
        pad_content = "pag_name:{},content:{}".format(pad, content["text"])
    pad_content_length = len(pad_content)
    if pad_content_length <= 1500:
        is_ok, err_msg = audit_client.check_content_ok(pad_content)
        if not is_ok:
            logger.info("find the result is:{}".format(pad))
            return get_reject_describe(pad, community_etherpad, err_msg), empty_pad_name
    else:
        logger.info("find the pad: {} and the content length gt 1500 and is:{}".format(pad, pad_content_length))
        for i in range(0, pad_content_length, 1500):
            start_index = i
            end_index = 1500 + i
            if end_index > pad_content_length:
                end_index = pad_content_length
            is_ok, err_msg = audit_client.check_content_ok(pad_content[start_index: end_index])
            if not is_ok:
                logger.info("find the result is:{}".format(pad))
                return get_reject_describe(pad, community_etherpad, err_msg), empty_pad_name
    return list(), empty_pad_name


@func_retry()
def scan_single_community(community_etherpad):
    if not isinstance(community_etherpad, CommunityEtherpad):
        raise RuntimeError("community_etherpad must be CommunityEtherpad")
    audit_client = AuditClient(community_etherpad.scan_url, community_etherpad.scan_token)
    elc = EtherpadLiteClient(apiKey=community_etherpad.etherpad_token,
                             baseUrl=community_etherpad.etherpad_url)
    all_pads = elc.listAllPads()
    logger.info("find the pads count:{}".format(len(all_pads["padIDs"])))
    scan_list = list()
    empty_pad_name = list()
    for pad in all_pads["padIDs"]:
        scan_single_list, empty_pad_names = work(elc, audit_client, pad, community_etherpad)
        if scan_single_list:
            scan_list.extend(scan_single_list)
        if empty_pad_names:
            empty_pad_name.extend(empty_pad_names)
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
        scan_url=config_obj["scan_url"],
        scan_token=config_obj["scan_token"],
        scan_version_history=config_obj["scan_version_history"],
    )) for community in config_obj["community_etherpad"]]
    wait(all_tasks)


# noinspection PyTypeChecker,SpellCheckingInspection
def generate_sensitive_html():
    cleaned_info = ScanResult().result
    cleaned_info = sorted(cleaned_info, key=lambda x: (x["community"]), reverse=True)
    pd.set_option('display.width', 800)
    pd.set_option('display.max_colwidth', 150)
    pd.set_option('colheader_justify', 'center')
    pd.options.display.html.border = 2
    df = pd.DataFrame.from_dict(cleaned_info)
    df_style = df.style.hide()
    html = df_style.to_html()
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
    df_style = df.style.hide()
    html = df_style.to_html()
    content = _notify_count_template.format(html)
    template_content = _html_template.replace(r"{{template}}", content)
    return template_content


def send_email(config_obj):
    logger.info("----------start to send email---------")
    smtp_obj = smtplib.SMTP(config_obj["mta_ip"], config_obj["mta_port"])
    smtp_obj.login(config_obj["mta_username"], config_obj["mta_password"])
    receives = config_obj["mta_receivers"].split(";")
    text = generate_sensitive_html()
    message = MIMEText(text, "html", 'utf-8')
    message['Subject'] = Header(config_obj["mta_subject_sensor"], 'utf-8')
    message['To'] = ",".join(receives)
    smtp_obj.sendmail(config_obj["mta_sender"], receives, message.as_string())

    text = generate_count_html()
    message = MIMEText(text, "html", 'utf-8')
    message['Subject'] = Header(config_obj["mta_subject_count"], 'utf-8')
    message['To'] = ",".join(receives)
    smtp_obj.sendmail(config_obj["mta_sender"], receives, message.as_string())


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
