#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
微步在线 IP / 域名 / 文件哈希 混合查询工具（图形界面版）

功能:
    - 默认不预置 API Key，可修改 / 保存 API Key
    - 批量混合查询 IP、域名与文件哈希（自动识别类型）
    - IP:  调用 IP 信誉接口，展示基础信誉、威胁判定、标签与详情
    - 域名: 调用 /v3/scene/dns 失陷检测接口，展示域名信誉与失陷检测结果
    - 文件: 调用 /v3/file/report 文件信誉接口，支持 MD5 / SHA1 / SHA256
    - IP信誉 / 域名信誉 / 文件信誉 三视图
    - 恶意结果红色标注，非恶意不着色
    - 支持浅色 / 暗色模式切换
    - 导出 IP CSV / 域名 CSV / 文件 CSV / JSON
    - 双击结果行打开情报详情页
"""

import csv
import ipaddress
import json
import os
import re
import sys
import threading
import time
import webbrowser
from datetime import datetime

import requests

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import tkinter.font as tkfont
from tkinter.scrolledtext import ScrolledText

IP_API_URL = "https://api.threatbook.cn/v3/scene/ip_reputation"
DOMAIN_API_URL = "https://api.threatbook.cn/v3/scene/dns"
FILE_API_URL = "https://api.threatbook.cn/v3/file/report"

BATCH_SIZE = 100          # IP/域名接口单次上限
NETWORK_MAX_ATTEMPTS = 3  # 网络临时异常自动重试次数（含首次请求）
APP_NAME = "微步IP/域名/文件信誉查询API调用"
VERSION = "2.5.4"

CONFIG_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "ThreatBookIPReputation")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
CACHE_FILE = os.path.join(CONFIG_DIR, "cache.json")


def resource_path(name):
    """兼容源码运行与 PyInstaller 打包后的资源定位。"""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


APP_ICON_ICO = resource_path("app.ico")
APP_ICON_PNG = resource_path("app.png")


def _set_app_user_model_id():
    """Windows: 设置 AppUserModelID，确保任务栏/开始菜单使用本程序图标而非 Python 默认图标。"""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "ThreatBook.IPDomainQuery")
    except Exception:
        pass

# 默认不预置 API Key，需由用户在界面中填写并保存
DEFAULT_API_KEY = ""

# 判定为恶意的威胁类型（英文 + 中文，lang=zh 时接口返回中文）
MALICIOUS_JUDGMENTS = {
    # 主类型
    "C2", "远控", "Botnet", "僵尸网络", "Hijacked", "劫持", "Phishing", "钓鱼",
    "Malware", "恶意软件", "Exploit", "漏洞利用", "Scanner", "扫描", "Zombie", "傀儡机",
    "Spam", "垃圾邮件", "Brute Force", "暴力破解",
    # 子类
    "MiningPool", "公共矿池", "CoinMiner", "私有矿池", "Fake Website", "仿冒网站",
    "Sinkhole C2", "安全机构接管 C2", "SSH Brute Force", "SSH暴力破解",
    "FTP Brute Force", "FTP暴力破解", "SMTP Brute Force", "SMTP暴力破解",
    "Http Brute Force", "HTTP AUTH暴力破解", "Web Login Brute Force", "撞库",
}

THREAT_LEVEL_ZH = {
    "malicious": "恶意",
    "suspicious": "可疑",
    "clean": "安全",
    "unknown": "未知",
    "": "未知",
}

CONFIDENCE_ZH = {
    "low": "低",
    "medium": "中",
    "high": "高",
    "": "-",
}

SEVERITY_ZH = {
    "critical": "严重",
    "high": "高",
    "medium": "中",
    "low": "低",
    "info": "无威胁",
    "": "-",
}

FILE_THREAT_LEVEL_ZH = {
    "malicious": "恶意",
    "suspicious": "可疑",
    "clean": "安全",
    "unknown": "未知",
    "": "未知",
}

# 微步云 API response_code 中文说明。错误码最终会显示在结果表“详情链接”列。
RESPONSE_CODE_ZH = {
    0: "成功",
    1: "部分成功，请检查格式错误或批量数量限制",
    2: "没有数据",
    3: "任务进行中",
    4: "未发现报告：微步库暂未收录或报告暂不可用",
    5: "没有反病毒扫描引擎检测数据",
    6: "URL 下载文件失败",
    7: "URL 下载文件中",
    -1: "调用失败：账户、API Key、访问 IP、参数或权限异常",
    -2: "无效的 API 接口",
    -3: "接口请求参数必须项缺失",
    -4: "触发访问频次限制或超出每天/每月/总计访问限制",
    -5: "系统错误",
    -6: "模型报错",
    -7: "请求或返回内容包含受限信息",
    -8: "问题和网络安全无关，已拒绝回答",
    -9: "超出当前模型能力覆盖范围",
    -10: "请求 tokens 长度过长，超过模型限制",
    -11: "查询返回超时",
}

# response_code 相同但 verbose_msg 不同，需要按英文原文进一步翻译。
RESPONSE_VERBOSE_ZH = {
    "OK, Beyond Limitation from": "部分成功，从某个 IP 或域名起超出请求次数限制",
    "OK, Invalid data format": "部分成功，部分 IP/域名/漏洞编号格式错误，已跳过无效项",
    "Invalid Account Status": "账户状态无效，请联系微步在线工作人员",
    "Invalid Access IP": "无效的访问 IP，请检查 API Key 绑定的白名单",
    "Invalid API Key": "无效的 API Key，请输入正确的 Key",
    "Invalid Key Status": "API Key 状态无效，当前 Key 已被禁用",
    "Invalid Parameter": "无效的 API 接口参数",
    "No Access to API Method": "没有访问接口权限",
    "Expired API Key": "API Key 已过期，请联系微步在线产品对接人",
    "Empty File": "上传的是空文件，请确认是否选择错误",
    "File Size Too Large": "上传文件过大，文件大小不能超过 100M",
    "File Name Too Long": "上传文件名过长，不能超过 128 字节",
    "NO_AUTHORITY": "隐私样本，无法返回报告信息",
    "Invalid Cursor": "无效的 Cursor，任务记录已超过一天或该 Cursor 已使用过",
    "No Data": "没有数据",
    "In Progress": "任务进行中，报告正在生成，请稍后查询",
    "No Report Found": "未发现报告：微步库暂未收录或报告暂不可用",
    "SAMPLE_NOT_FOUND": "样本不存在：微步样本库未收录该文件哈希",
    "No MultiEngines Data": "没有反病毒扫描引擎检测数据",
    "URL Download Fail": "URL 下载文件失败",
    "URL Downloading": "URL 下载文件中，请稍后重试",
    "Invalid API Method": "无效的 API 接口，请确认接口地址是否正确",
    "Required": "接口请求参数必须项缺失",
    "Frequent Limitation": "触发访问频次限制，请降低请求频率后重试",
    "Beyond Daily/Monthly/Total Limitation": "超出每天/每月/总计访问限制，请检查接口授权额度",
    "System Error": "系统错误，请联系微步在线产品对接人",
    "Model Error": "模型报错，请检查请求参数或稍后重试",
    "Contains Restricted Content": "请求或返回内容包含敏感信息，请调整查询内容",
    "Query Not Relevant to Cybersecurity, Declined": "问题和网络安全无关，已拒绝回答",
    "Query Beyond Model Capabilities": "超出当前模型能力覆盖范围",
    "Input Token Limit Exceeded": "请求 tokens 长度过长，超过模型限制",
    "Query Timeout": "查询返回超时，请稍后重试或缩小查询范围",
}

# 浅色 / 暗色主题调色板（保证底色与字体颜色对比明显）
THEMES = {
    "light": {
        "root_bg": "#eef0f3",
        "panel_bg": "#f7f8fa",
        "text_bg": "#ffffff",
        "text_fg": "#1f2328",
        "field_bg": "#ffffff",
        "field_fg": "#1f2328",
        "row_bg": "#ffffff",
        "row_fg": "#1f2328",
        "row_alt": "#eef1f5",
        "heading_bg": "#dfe3e8",
        "heading_fg": "#1f2328",
        "select_bg": "#bcd6f7",
        "select_fg": "#10233a",
        "malice_fg": "#d32f2f",
        "border": "#c4c9d0",
        "insert": "#1f2328",
    },
    "dark": {
        "root_bg": "#17181b",
        "panel_bg": "#1f2125",
        "text_bg": "#232529",
        "text_fg": "#f2f3f5",
        "field_bg": "#2a2d32",
        "field_fg": "#f2f3f5",
        "row_bg": "#232529",
        "row_fg": "#f2f3f5",
        "row_alt": "#292c31",
        "heading_bg": "#3a3e45",
        "heading_fg": "#ffffff",
        "select_bg": "#3b6ea5",
        "select_fg": "#ffffff",
        "malice_fg": "#ff6b6b",
        "border": "#3a3e45",
        "insert": "#f2f3f5",
    },
}


# ----------------------------------------------------------------------------
# 配置读写
# ----------------------------------------------------------------------------
def load_config():
    cfg = {"apikey": "", "lang": "zh", "realtime": False, "dark": False}
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
            if isinstance(saved, dict):
                cfg.update(saved)
    except Exception:
        pass
    # 只读取用户手动保存的 Key；没有配置文件时默认为空
    cfg["apikey"] = (cfg.get("apikey") or "").strip()
    return cfg


def save_config(cfg):
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        messagebox.showerror(APP_NAME, f"保存配置失败：{e}")
        return False


# ----------------------------------------------------------------------------
# 本地结果缓存（已查询过的 IP / 域名保留信誉结果，避免重复消耗 API 额度）
# ----------------------------------------------------------------------------
def load_cache():
    """从本地文件读取缓存，返回 {"ip": {...}, "domain": {...}, "file": {...}}。"""
    empty = {"ip": {}, "domain": {}, "file": {}}
    try:
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                ip = data.get("ip") if isinstance(data.get("ip"), dict) else {}
                dm = data.get("domain") if isinstance(data.get("domain"), dict) else {}
                fm = data.get("file") if isinstance(data.get("file"), dict) else {}
                # 旧版域名缓存来自 /v3/domain/query（含 samples），与 scene/dns
                # 返回结构不同，直接丢弃让这些域名重新按新接口查询。
                dm = {k: v for k, v in dm.items()
                      if isinstance(v, dict) and "is_malicious" in v}
                return {"ip": ip, "domain": dm, "file": fm}
    except Exception:
        pass
    return empty


def save_cache(cache):
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False)
        return True
    except Exception:
        return False


def clear_cache_file():
    try:
        if os.path.exists(CACHE_FILE):
            os.remove(CACHE_FILE)
        return True
    except Exception:
        return False


# ----------------------------------------------------------------------------
# 输入解析与类型识别
# ----------------------------------------------------------------------------
def file_hash_type(token):
    """识别文件哈希类型，支持 MD5 / SHA1 / SHA256。"""
    t = str(token).strip().lower()
    if re.fullmatch(r"[0-9a-f]{32}", t):
        return "md5"
    if re.fullmatch(r"[0-9a-f]{40}", t):
        return "sha1"
    if re.fullmatch(r"[0-9a-f]{64}", t):
        return "sha256"
    return ""


def classify(token):
    """返回 'ip'、'domain' 或 'file'。"""
    try:
        ipaddress.ip_address(token)
        return "ip"
    except ValueError:
        pass
    if file_hash_type(token):
        return "file"
    return "domain"


def normalize_domain(token):
    """把可能带协议/路径/端口/大小写的输入规范成纯域名。"""
    t = token.strip().lower()
    t = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", t)   # 去掉 http:// 等
    t = t.split("/")[0]                            # 去掉路径
    t = t.split("?")[0].split("#")[0]              # 去掉 query / fragment
    t = t.split("@")[-1]                           # 去掉 user@
    if t.count(":") == 1:                          # 去掉端口（IPv6 不含单个冒号）
        t = t.rsplit(":", 1)[0]
    return t.strip(".")


def parse_input(text):
    """解析界面输入，返回 (资源列表, 资源->类型) 去重有序。"""
    raw = (text.replace(",", " ").replace("，", " ")
               .replace(";", " ").replace("；", " ")
               .replace("\t", " ").replace("\n", " "))
    tokens = [t.strip() for t in raw.split() if t.strip()]
    items, seen = [], set()
    for tok in tokens:
        kind = classify(tok)
        if kind == "ip":
            key = tok
        elif kind == "file":
            key = tok.lower()
        else:
            key = normalize_domain(tok)
        if not key or key in seen:
            continue
        seen.add(key)
        items.append((key, kind))
    return items


# ----------------------------------------------------------------------------
# 接口调用
# ----------------------------------------------------------------------------
def _network_error_zh(exc):
    """将 requests / socket 网络异常转换为可读中文提示。"""
    raw = str(exc)
    cause = str(getattr(exc, "__cause__", "") or "")
    text = f"{raw} {cause}"
    low = text.lower()
    if ("connectionreseterror" in low or "10054" in text or "远程主机强迫关闭" in text
            or "connection aborted" in low or "connection reset" in low):
        return "远程服务器强制关闭了连接（10054），可能是网络波动或服务端临时限制"
    if "read timed out" in low or "timed out" in low or "timeout" in low:
        return "连接或读取超时"
    if "namenotresolved" in low or "name resolution" in low or "getaddrinfo" in low:
        return "无法解析微步接口域名，请检查 DNS 或网络连接"
    if "proxyerror" in low or "proxy" in low:
        return "代理连接异常，请检查系统代理设置"
    if "sslerror" in low or "certificate" in low:
        return "HTTPS/SSL 证书校验失败"
    if "max retries exceeded" in low:
        return "连接连续失败，已达到重试上限"
    return "网络请求异常，请检查网络连接后重试"


def _request_json(url, params, endpoint, timeout=30):
    """请求微步接口并解析 JSON；临时网络异常自动重试，最终返回中文错误。"""
    last_exc = None
    for attempt in range(1, NETWORK_MAX_ATTEMPTS + 1):
        try:
            resp = requests.get(
                url,
                params=params,
                timeout=timeout,
                headers={"Connection": "close"},
            )
            resp.raise_for_status()
            try:
                return resp.json()
            except ValueError as exc:
                raise RuntimeError(f"[{endpoint}] 接口返回内容解析失败：返回内容不是有效 JSON") from exc
        except RuntimeError:
            raise
        except requests.exceptions.HTTPError as exc:
            status = getattr(getattr(exc, "response", None), "status_code", "未知")
            if attempt < NETWORK_MAX_ATTEMPTS and (status == 429 or (isinstance(status, int) and status >= 500)):
                time.sleep(0.8 * attempt)
                continue
            if status == 429:
                raise RuntimeError(f"[{endpoint}] 接口请求过于频繁：HTTP 429，请稍后重试") from exc
            if isinstance(status, int) and status >= 500:
                raise RuntimeError(f"[{endpoint}] 微步服务端暂时异常：HTTP {status}，请稍后重试") from exc
            raise RuntimeError(f"[{endpoint}] 接口请求失败：HTTP {status}") from exc
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.ProxyError) as exc:
            last_exc = exc
            if attempt < NETWORK_MAX_ATTEMPTS:
                time.sleep(0.8 * attempt)
                continue
            raise RuntimeError(
                f"[{endpoint}] 网络连接失败：{_network_error_zh(exc)}（已自动尝试 {attempt} 次）"
            ) from exc
        except requests.exceptions.RequestException as exc:
            last_exc = exc
            if attempt < NETWORK_MAX_ATTEMPTS:
                time.sleep(0.8 * attempt)
                continue
            raise RuntimeError(
                f"[{endpoint}] 网络请求失败：{_network_error_zh(exc)}（已自动尝试 {attempt} 次）"
            ) from exc
    raise RuntimeError(f"[{endpoint}] 网络请求失败：{_network_error_zh(last_exc)}")

def _response_code_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _translate_verbose_msg(raw_msg, code=None):
    """把微步 verbose_msg 转为中文；保留参数值等动态信息。"""
    raw = str(raw_msg or "").strip()
    if not raw:
        return RESPONSE_CODE_ZH.get(code, "未知响应码")
    normalized = re.sub(r"\s+", " ", raw).replace("，", ",").replace("：", ":")
    normalized = re.sub(r"\s*,\s*", ", ", normalized)
    normalized = re.sub(r"\s*:\s*", ": ", normalized)
    lower = normalized.lower()
    for en_msg, zh_msg in sorted(RESPONSE_VERBOSE_ZH.items(), key=lambda x: len(x[0]), reverse=True):
        key = en_msg.lower()
        if lower == key or lower.startswith(key):
            tail = normalized[len(en_msg):].lstrip(" :")
            return f"{zh_msg}：{tail}" if tail else zh_msg
    if any("\u4e00" <= ch <= "\u9fff" for ch in raw):
        return raw
    return RESPONSE_CODE_ZH.get(code, raw or "未知响应码")


def response_code_to_chinese(payload):
    """返回完整中文错误说明：响应码 + 中文含义 + 接口原始消息。"""
    code = _response_code_int(payload.get("response_code"))
    raw = str(payload.get("verbose_msg") or "").strip()
    zh = _translate_verbose_msg(raw, code)
    if code is None:
        prefix = "响应码未知"
    else:
        prefix = f"响应码 {code}"
    detail = f"{prefix}：{zh}"
    if raw and raw not in detail:
        detail += f"（{raw}）"
    return detail


def _raise_api_error(payload, endpoint):
    code = _response_code_int(payload.get("response_code"))
    if code == 0:
        return
    msg = str(payload.get("verbose_msg") or "")
    hint = ""
    if code == -1 and ("Invalid Access IP" in msg or "访问IP" in msg):
        hint = "\n\n请到微步控制台「我的KEY」中，把当前出口 IP 加入白名单。"
    elif code == -1 and ("No Access to API Method" in msg or "没有访问接口权限" in msg):
        hint = "\n\n当前 API Key 未开通该接口权限，请到微步控制台「API权限」中申请/开通对应接口。"
    elif code == -4:
        hint = "\n\n已触发限速或超出配额，请稍后重试或检查接口额度。"
    raise RuntimeError(f"[{endpoint}] {response_code_to_chinese(payload)}{hint}")


def query_ips(ips, apikey, lang="zh", realtime=False, timeout=30):
    """批量查询 IP（<=100），返回 {ip: result}。"""
    params = {
        "resource": ",".join(ips),
        "apikey": apikey,
        "lang": lang,
        "realtime_verdict": "true" if realtime else "false",
    }
    payload = _request_json(IP_API_URL, params, "IP信誉", timeout=timeout)
    _raise_api_error(payload, "IP信誉")
    data = payload.get("data", {}) or {}
    if isinstance(data.get("ips"), dict):
        return data["ips"]
    return data


def query_file_report(resource, apikey, timeout=30):
    """调用 /v3/file/report 查询单个文件哈希（MD5 / SHA1 / SHA256）。"""
    params = {
        "resource": resource,
        "apikey": apikey,
        "query_fields": "summary,multiengines",
    }
    payload = _request_json(FILE_API_URL, params, "文件信誉", timeout=timeout)
    _raise_api_error(payload, "文件信誉")
    data = payload.get("data", {}) or {}
    if not isinstance(data, dict):
        data = {}
    else:
        data = dict(data)
    if payload.get("permalink"):
        data["permalink"] = payload.get("permalink")
    return data


def query_scene_dns(resources, apikey, lang="zh", realtime=False, timeout=30):
    """调用失陷检测接口 /v3/scene/dns（<=100 批量）。

    返回 (ips_map, domains_map)，两者均为 {资源: 结果}。
    """
    params = {
        "resource": ",".join(resources),
        "apikey": apikey,
        "lang": lang,
        "realtime_verdict": "true" if realtime else "false",
    }
    payload = _request_json(DOMAIN_API_URL, params, "失陷检测", timeout=timeout)
    _raise_api_error(payload, "失陷检测")
    data = payload.get("data", {}) or {}
    ips = data.get("ips") if isinstance(data.get("ips"), dict) else {}
    domains = data.get("domains") if isinstance(data.get("domains"), dict) else {}
    return ips, domains


# ----------------------------------------------------------------------------
# 结果格式化
# ----------------------------------------------------------------------------
def fmt_location(location):
    if not isinstance(location, dict):
        return ""
    parts = [str(location.get(k)).strip() for k in ("country", "province", "city") if location.get(k)]
    text = " / ".join(parts)
    lng, lat = location.get("lng"), location.get("lat")
    if lng and lat:
        text = f"{text} ({lng}, {lat})" if text else f"({lng}, {lat})"
    return text


def fmt_tags_classes(tags_classes):
    if not isinstance(tags_classes, list) or not tags_classes:
        return ""
    lines = []
    for item in tags_classes:
        if not isinstance(item, dict):
            continue
        tags_type = item.get("tags_type") or ""
        tags = item.get("tags")
        if isinstance(tags, (list, tuple)):
            tags_text = "、".join(str(t) for t in tags if t)
        else:
            tags_text = str(tags) if tags else ""
        label = f"{tags_type}: {tags_text}" if tags_type else tags_text
        if label:
            lines.append(label)
    return "；".join(lines)


def verdict_from_judgments(judgments):
    """由威胁判定推导 恶意/可疑/未知。"""
    if not isinstance(judgments, list) or not judgments:
        return "未知"
    names = {str(j) for j in judgments}
    if names & MALICIOUS_JUDGMENTS:
        return "恶意"
    return "非恶意"


def fmt_domain_categories(categories):
    """格式化 scene/dns 返回的域名分类。"""
    if not isinstance(categories, dict):
        return ""
    first = categories.get("first_cats")
    second = categories.get("second_cats")
    parts = []
    if isinstance(first, (list, tuple)):
        parts.extend(str(x) for x in first if x)
    elif first:
        parts.append(str(first))
    if second and str(second) not in parts:
        parts.append(str(second))
    return " / ".join(parts)


def verdict_from_file_item(item):
    """根据文件 summary 推断恶意/可疑/安全/未知。"""
    if not isinstance(item, dict):
        return "未知"
    summary = item.get("summary") if isinstance(item.get("summary"), dict) else {}
    level = str(summary.get("threat_level", "")).lower()
    if level == "malicious":
        return "恶意"
    if level == "suspicious":
        return "可疑"
    if summary.get("is_whitelist") is True:
        return "非恶意"
    if level in ("clean", "unknown") and summary.get("multi_engines"):
        try:
            detected = int(str(summary.get("multi_engines", "0/0")).split("/", 1)[0])
        except Exception:
            detected = 0
        if detected > 0:
            return "恶意"
    if level == "clean":
        return "非恶意"
    return "未知"


def verdict_from_item(item):
    """优先按接口 is_malicious 判定，缺失时回退到 judgments。"""
    if not isinstance(item, dict):
        return "未知"
    is_mal = item.get("is_malicious")
    if is_mal is True:
        return "恶意"
    if is_mal is False:
        return "非恶意"
    return verdict_from_judgments(item.get("judgments") or [])


# ----------------------------------------------------------------------------
# 主界面
# ----------------------------------------------------------------------------
class App:
    def __init__(self, root):
        self.root = root
        self.cfg = load_config()
        self.results = {}     # 资源 -> {"type":..., "data":...}
        self.row_order = []
        self.cache = load_cache()   # 本地结果缓存 {"ip": {...}, "domain": {...}, "file": {...}}
        self.cache.setdefault("ip", {})
        self.cache.setdefault("domain", {})
        self.cache.setdefault("file", {})
        self.querying = False

        root.title(f"{APP_NAME} v{VERSION}")
        root.geometry("1180x780")
        root.minsize(980, 640)
        self._set_icon()

        self._build_style()
        self._build_widgets()
        self._apply_theme()

    def _build_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Treeview", rowheight=26, font=("Microsoft YaHei UI", 9),
                        borderwidth=0, relief="flat")
        style.configure("Treeview.Heading", font=("Microsoft YaHei UI", 9, "bold"),
                        padding=(4, 6))
        style.map("Treeview.Heading", relief=[("active", "flat")])
        style.configure("TButton", font=("Microsoft YaHei UI", 9), padding=6)
        style.configure("Small.TButton", font=("Microsoft YaHei UI", 8), padding=(6, 2))
        style.configure("TLabel", font=("Microsoft YaHei UI", 9))
        style.configure("TCheckbutton", font=("Microsoft YaHei UI", 9))
        style.configure("TRadiobutton", font=("Microsoft YaHei UI", 9))
        style.configure("TLabelframe.Label", font=("Microsoft YaHei UI", 9, "bold"))
        self._tree_font = tkfont.Font(family="Microsoft YaHei UI", size=9)

    def _fit_tree_row(self, tree, columns, values):
        """按单元格内容自动加宽列，避免长文本在列内被截断。"""
        caps = {
            "carrier": 700,
            "location": 1000,
            "judgments": 1800,
            "categories": 1400,
            "tags": 1400,
            "file_name": 900,
            "malware_type": 800,
            "malware_family": 1000,
            "permalink": 2800,
        }
        for column, value in zip(columns, values):
            text_value = str(value or "")
            if not text_value:
                continue
            try:
                needed = self._tree_font.measure(text_value) + 28
            except Exception:
                needed = len(text_value) * 12 + 28
            current = int(float(tree.column(column, "width")))
            target = max(current, min(needed, caps.get(column, 1000)))
            if target > current:
                tree.column(column, width=target, stretch=False)

    def _bind_horizontal_wheel(self, tree):
        """Shift + 鼠标滚轮横向滚动结果表；兼容部分鼠标的横向滚轮。"""
        def scroll_x(units):
            tree.xview_scroll(units, "units")
            return "break"

        tree.bind("<Shift-MouseWheel>", lambda event: scroll_x(-6 if event.delta > 0 else 6))
        tree.bind("<Shift-Button-4>", lambda _event: scroll_x(-6))
        tree.bind("<Shift-Button-5>", lambda _event: scroll_x(6))

    def _apply_theme(self):
        """按当前「浅色 / 暗色」设置刷新界面配色。"""
        t = THEMES["dark" if self.dark_var.get() else "light"]
        self._theme = t
        style = ttk.Style()
        style.configure(".", background=t["panel_bg"], foreground=t["text_fg"])
        style.configure("TFrame", background=t["panel_bg"])
        style.configure("TLabel", background=t["panel_bg"], foreground=t["text_fg"])
        for betn in ("TCheckbutton", "TRadiobutton"):
            style.configure(betn, background=t["panel_bg"], foreground=t["text_fg"],
                            indicatorbackground=t["field_bg"],
                            indicatorforeground=t["text_fg"],
                            indicatorcolor=t["text_fg"],
                            upperbordercolor=t["border"],
                            lowerbordercolor=t["border"],
                            focuscolor=t["panel_bg"], bordercolor=t["border"])
            style.map(betn,
                      background=[("active", t["panel_bg"]),
                                  ("pressed", t["panel_bg"]),
                                  ("selected", t["panel_bg"])],
                      foreground=[("active", t["text_fg"]),
                                  ("selected", t["text_fg"]),
                                  ("disabled", t["border"])],
                      indicatorbackground=[("selected", t["select_bg"]),
                                           ("active", t["field_bg"])],
                      indicatorcolor=[("selected", t["select_fg"]),
                                      ("disabled", t["border"])],
                      upperbordercolor=[("selected", t["select_bg"]),
                                        ("active", t["border"])],
                      lowerbordercolor=[("selected", t["select_bg"]),
                                        ("active", t["border"])])
        style.configure("TLabelframe", background=t["panel_bg"], bordercolor=t["border"])
        style.configure("TLabelframe.Label", background=t["panel_bg"], foreground=t["text_fg"])
        style.configure("TButton", background=t["field_bg"], foreground=t["field_fg"])
        style.configure("Small.TButton", background=t["field_bg"], foreground=t["field_fg"])
        style.map("TButton",
                  background=[("active", t["select_bg"]), ("pressed", t["select_bg"])],
                  foreground=[("disabled", t["border"])])
        style.map("Small.TButton",
                  background=[("active", t["select_bg"]), ("pressed", t["select_bg"]),
                              ("disabled", t["panel_bg"])],
                  foreground=[("active", t["select_fg"]), ("pressed", t["select_fg"]),
                              ("disabled", t["border"])])
        style.configure("TEntry", fieldbackground=t["field_bg"], foreground=t["field_fg"],
                        insertcolor=t["field_fg"])
        style.configure("TPanedwindow", background=t["panel_bg"])
        style.configure("TNotebook", background=t["panel_bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=t["field_bg"], foreground=t["field_fg"],
                        padding=(12, 6))
        style.map("TNotebook.Tab",
                  background=[("selected", t["select_bg"]), ("active", t["select_bg"])],
                  foreground=[("selected", t["select_fg"]), ("active", t["select_fg"])])
        style.configure("Treeview", background=t["row_bg"], fieldbackground=t["row_bg"],
                        foreground=t["row_fg"], bordercolor=t["border"])
        style.configure("Treeview.Heading", background=t["heading_bg"],
                        foreground=t["heading_fg"], relief="flat")
        style.map("Treeview",
                  background=[("selected", t["select_bg"])],
                  foreground=[("selected", t["select_fg"])])
        style.map("Treeview.Heading",
                  background=[("active", t["heading_bg"])],
                  foreground=[("active", t["heading_fg"])])

        self.root.configure(bg=t["root_bg"])
        self.input_text.configure(bg=t["text_bg"], fg=t["text_fg"],
                                  insertbackground=t["insert"],
                                  selectbackground=t["select_bg"],
                                  selectforeground=t["select_fg"])
        for tv in (self.tree, self.domain_tree, self.file_tree):
            tv.tag_configure("mal", foreground=t["malice_fg"])

    def _toggle_theme(self):
        self._apply_theme()
        self.save_cfg(silent=True)

    def _set_icon(self):
        """设置窗口 / 任务栏图标（打包与源码运行均可）。"""
        try:
            if os.path.exists(APP_ICON_ICO):
                self.root.iconbitmap(default=APP_ICON_ICO)
        except Exception:
            pass
        try:
            if os.path.exists(APP_ICON_PNG):
                self._icon_img = tk.PhotoImage(file=APP_ICON_PNG)
                self.root.iconphoto(True, self._icon_img)
        except Exception:
            pass

    def _build_widgets(self):
        # ---------- 配置 ----------
        top = ttk.LabelFrame(self.root, text="配置", padding=10)
        top.pack(fill="x", padx=12, pady=(12, 6))

        ttk.Label(top, text="API Key：").grid(row=0, column=0, sticky="w")
        self.apikey_var = tk.StringVar(value=self.cfg.get("apikey", ""))
        self.apikey_entry = ttk.Entry(top, textvariable=self.apikey_var, width=70, show="*")
        self.apikey_entry.grid(row=0, column=1, columnspan=4, sticky="we", padx=(4, 8))
        self.apikey_entry.bind("<Return>", lambda _e: self.save_cfg())
        self.show_key_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="显示", variable=self.show_key_var,
                        command=self._toggle_key).grid(row=0, column=5, sticky="w")

        ttk.Label(top, text="返回语言：").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.lang_var = tk.StringVar(value=self.cfg.get("lang", "zh"))
        ttk.Radiobutton(top, text="中文", variable=self.lang_var, value="zh").grid(row=1, column=1, sticky="w", pady=(8, 0))
        ttk.Radiobutton(top, text="English", variable=self.lang_var, value="en").grid(row=1, column=2, sticky="w", pady=(8, 0))

        self.realtime_var = tk.BooleanVar(value=bool(self.cfg.get("realtime", False)))
        ttk.Checkbutton(top, text="仅当前有效情报（不勾选=含历史过期情报）",
                        variable=self.realtime_var).grid(row=1, column=3, columnspan=3, sticky="w", pady=(8, 0))

        self.dark_var = tk.BooleanVar(value=bool(self.cfg.get("dark", False)))
        ttk.Checkbutton(top, text="暗色模式", variable=self.dark_var,
                        command=self._toggle_theme).grid(row=2, column=0, columnspan=2, sticky="w", pady=(8, 0))
        ttk.Label(top, text="首次打开为空；填写后点「保存配置」或按回车即可长期生效。").grid(
            row=2, column=2, columnspan=4, sticky="w", pady=(8, 0))

        ttk.Button(top, text="保存配置", command=self.save_cfg).grid(row=0, column=6, rowspan=3, padx=(8, 0), sticky="ns")
        top.columnconfigure(1, weight=1)
        top.columnconfigure(3, weight=1)

        # ---------- 输入 ----------
        mid = ttk.LabelFrame(self.root, text="批量输入（IP、域名与文件哈希可混合；每行一个或用逗号/空格/分号分隔）", padding=10)
        mid.pack(fill="both", expand=False, padx=12, pady=6)

        self.input_text = ScrolledText(mid, height=6, font=("Consolas", 10), wrap="word")
        self.input_text.pack(fill="both", expand=True)

        btns = ttk.Frame(mid)
        btns.pack(fill="x", pady=(8, 0))
        self.query_btn = ttk.Button(btns, text="开始查询", command=self.on_query)
        self.query_btn.pack(side="left")
        ttk.Button(btns, text="清空输入", command=lambda: self.input_text.delete("1.0", "end")).pack(side="left", padx=6)
        ttk.Button(btns, text="导出 IP 结果 CSV", command=self.export_csv).pack(side="left", padx=6)
        ttk.Button(btns, text="导出域名结果 CSV", command=self.export_domains_csv).pack(side="left", padx=6)
        ttk.Button(btns, text="导出文件结果 CSV", command=self.export_files_csv).pack(side="left", padx=6)
        ttk.Button(btns, text="导出 JSON", command=self.export_json).pack(side="left", padx=6)
        self.count_label = ttk.Label(btns, text="待查询：0 个（IP 0 / 域名 0 / 文件 0）")
        self.count_label.pack(side="right")
        self.input_text.bind("<KeyRelease>", self._update_count)

        # ---------- 结果区（三视图标签页） ----------
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=12, pady=(6, 4))

        # IP 信誉
        res_frame = ttk.LabelFrame(notebook, text="IP信誉（仅展示 IP 查询结果，双击打开情报详情页；Shift+滚轮可左右滚动）", padding=8)
        notebook.add(res_frame, text="IP 信誉")
        res_cols = ("resource", "verdict", "carrier", "location", "judgments", "permalink")
        res_heads = ("IP", "判定", "运营商", "地理位置", "威胁判定", "详情链接")
        res_widths = (180, 70, 150, 230, 260, 300)
        res_align = {"resource": "w", "verdict": "center", "carrier": "w",
                     "location": "w", "judgments": "w", "permalink": "w"}
        self.tree = ttk.Treeview(res_frame, columns=res_cols, show="headings", selectmode="browse")
        for c, h, w in zip(res_cols, res_heads, res_widths):
            self.tree.heading(c, text=h, anchor=res_align[c])
            self.tree.column(c, width=w, anchor=res_align[c],
                             stretch=False)
        rvs = ttk.Scrollbar(res_frame, orient="vertical", command=self.tree.yview)
        rhs = ttk.Scrollbar(res_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=rvs.set, xscrollcommand=rhs.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        rvs.grid(row=0, column=1, sticky="ns")
        rhs.grid(row=1, column=0, sticky="ew")
        res_frame.rowconfigure(0, weight=1)
        res_frame.columnconfigure(0, weight=1)
        self.tree.bind("<Double-1>", self.on_resource_double_click)
        self._bind_horizontal_wheel(self.tree)

        # 域名信誉
        smp_frame = ttk.LabelFrame(
            notebook,
            text="域名信誉（失陷检测 / scene/dns，仅展示域名查询结果，双击打开域名情报详情页；Shift+滚轮可左右滚动）",
            padding=8,
        )
        notebook.add(smp_frame, text="域名信誉")
        dm_cols = ("resource", "verdict", "confidence", "severity", "judgments",
                   "categories", "tags", "permalink")
        dm_heads = ("域名", "判定", "可信度", "严重级别", "威胁判定", "域名分类", "标签", "详情链接")
        dm_widths = (170, 70, 70, 80, 190, 180, 220, 300)
        dm_align = {"resource": "w", "verdict": "center", "confidence": "center",
                    "severity": "center", "judgments": "w", "categories": "w",
                    "tags": "w", "permalink": "w"}
        self.domain_tree = ttk.Treeview(smp_frame, columns=dm_cols, show="headings", selectmode="browse")
        for c, h, w in zip(dm_cols, dm_heads, dm_widths):
            self.domain_tree.heading(c, text=h, anchor=dm_align[c])
            self.domain_tree.column(c, width=w, anchor=dm_align[c],
                                    stretch=False)
        svs = ttk.Scrollbar(smp_frame, orient="vertical", command=self.domain_tree.yview)
        shs = ttk.Scrollbar(smp_frame, orient="horizontal", command=self.domain_tree.xview)
        self.domain_tree.configure(yscrollcommand=svs.set, xscrollcommand=shs.set)
        self.domain_tree.grid(row=0, column=0, sticky="nsew")
        svs.grid(row=0, column=1, sticky="ns")
        shs.grid(row=1, column=0, sticky="ew")
        smp_frame.rowconfigure(0, weight=1)
        smp_frame.columnconfigure(0, weight=1)
        self.domain_tree.bind("<Double-1>", self.on_domain_double_click)
        self._bind_horizontal_wheel(self.domain_tree)

        # 文件信誉
        file_frame = ttk.LabelFrame(
            notebook,
            text="文件信誉（/v3/file/report，仅展示 MD5 / SHA1 / SHA256 查询结果，双击打开详情页；Shift+滚轮可左右滚动）",
            padding=8,
        )
        notebook.add(file_frame, text="文件信誉")
        file_cols = ("resource", "hash_type", "verdict", "threat_level", "score",
                     "file_name", "file_type", "malware_type", "malware_family",
                     "multi_engines", "whitelist", "permalink")
        file_heads = ("哈希", "类型", "判定", "威胁等级", "评分", "文件名", "文件类型",
                      "恶意类型", "家族", "引擎检出", "白名单", "详情链接")
        file_widths = (260, 70, 70, 80, 60, 180, 90, 130, 150, 90, 70, 300)
        file_align = {"resource": "w", "hash_type": "center", "verdict": "center",
                      "threat_level": "center", "score": "center", "file_name": "w",
                      "file_type": "center", "malware_type": "w", "malware_family": "w",
                      "multi_engines": "center", "whitelist": "center", "permalink": "w"}
        self.file_tree = ttk.Treeview(file_frame, columns=file_cols, show="headings", selectmode="browse")
        for c, h, w in zip(file_cols, file_heads, file_widths):
            self.file_tree.heading(c, text=h, anchor=file_align[c])
            self.file_tree.column(c, width=w, anchor=file_align[c],
                                  stretch=False)
        fvs = ttk.Scrollbar(file_frame, orient="vertical", command=self.file_tree.yview)
        fhs = ttk.Scrollbar(file_frame, orient="horizontal", command=self.file_tree.xview)
        self.file_tree.configure(yscrollcommand=fvs.set, xscrollcommand=fhs.set)
        self.file_tree.grid(row=0, column=0, sticky="nsew")
        fvs.grid(row=0, column=1, sticky="ns")
        fhs.grid(row=1, column=0, sticky="ew")
        file_frame.rowconfigure(0, weight=1)
        file_frame.columnconfigure(0, weight=1)
        self.file_tree.bind("<Double-1>", self.on_file_double_click)
        self._bind_horizontal_wheel(self.file_tree)

        # 底部状态栏：查询状态 + 本地缓存统计 + 清空缓存 + 作者署名
        self.status_var = tk.StringVar(value="就绪")
        self.cache_info_var = tk.StringVar(value="本地缓存：IP 0 / 域名 0 / 文件 0 ｜ 本次命中缓存：0")
        status_bar = ttk.Frame(self.root)
        status_bar.pack(fill="x", side="bottom", before=notebook)
        status_bar.columnconfigure(0, weight=1)
        ttk.Label(status_bar, textvariable=self.status_var, anchor="w",
                  relief="sunken", padding=(8, 3)).grid(row=0, column=0, sticky="ew")
        ttk.Label(status_bar, textvariable=self.cache_info_var, anchor="center",
                  relief="sunken", padding=(8, 3)).grid(row=0, column=1, sticky="ns")
        ttk.Button(status_bar, text="清空缓存", command=self.clear_cache,
                   style="Small.TButton", width=8).grid(row=0, column=2, sticky="ns", padx=(4, 4), pady=1)
        ttk.Label(status_bar, text="作者：Uncledavid", anchor="e",
                  relief="sunken", padding=(8, 3)).grid(row=0, column=3, sticky="ns")
        self._refresh_cache_status()

    # ---------------- 事件 ----------------
    def _toggle_key(self):
        self.apikey_entry.configure(show="" if self.show_key_var.get() else "*")

    def _refresh_cache_status(self):
        """刷新底部常驻的本地缓存统计。"""
        if not hasattr(self, "cache_info_var"):
            return
        ip = self.cache.get("ip", {}) if isinstance(self.cache, dict) else {}
        dm = self.cache.get("domain", {}) if isinstance(self.cache, dict) else {}
        fm = self.cache.get("file", {}) if isinstance(self.cache, dict) else {}
        n_ip = len(ip) if isinstance(ip, dict) else 0
        n_dm = len(dm) if isinstance(dm, dict) else 0
        n_fm = len(fm) if isinstance(fm, dict) else 0
        hits = getattr(self, "_cached_hits", 0)
        self.cache_info_var.set(f"本地缓存：IP {n_ip} / 域名 {n_dm} / 文件 {n_fm} ｜ 本次命中缓存：{hits}")

    def _update_count(self, _event=None):
        items = parse_input(self.input_text.get("1.0", "end"))
        n_ip = sum(1 for _, k in items if k == "ip")
        n_dm = sum(1 for _, k in items if k == "domain")
        n_fm = sum(1 for _, k in items if k == "file")
        self.count_label.configure(text=f"待查询：{len(items)} 个（IP {n_ip} / 域名 {n_dm} / 文件 {n_fm}）")

    def save_cfg(self, silent=False):
        cfg = {"apikey": self.apikey_var.get().strip(), "lang": self.lang_var.get(),
               "realtime": bool(self.realtime_var.get()), "dark": bool(self.dark_var.get())}
        if save_config(cfg):
            self.cfg = cfg
            if not silent:
                self.status_var.set("配置已保存，下次启动自动加载")

    def on_query(self):
        if self.querying:
            return
        apikey = self.apikey_var.get().strip()
        if not apikey:
            messagebox.showwarning(APP_NAME, "请先填写 API Key。")
            return
        items = parse_input(self.input_text.get("1.0", "end"))
        if not items:
            messagebox.showwarning(APP_NAME, "请输入要查询的 IP、域名或文件哈希。")
            return

        self.cfg = {"apikey": apikey, "lang": self.lang_var.get(),
                    "realtime": bool(self.realtime_var.get()), "dark": bool(self.dark_var.get())}
        save_config(self.cfg)

        self.querying = True
        self.query_btn.configure(state="disabled")
        self._clear_results()
        self.status_var.set(f"正在查询 {len(items)} 个资源 ...")
        threading.Thread(target=self._query_worker, args=(items,), daemon=True).start()

    def _query_worker(self, items):
        lang = self.lang_var.get()
        realtime = bool(self.realtime_var.get())
        apikey = self.apikey_var.get().strip()
        total = len(items)
        done = 0
        try:
            ips = [k for k, t in items if t == "ip"]
            domains = [k for k, t in items if t == "domain"]
            files = [k for k, t in items if t == "file"]

            # ---- IP：命中缓存直接展示，未命中才批量调用接口 ----
            ip_miss = []
            for ip in ips:
                if ip in self.cache["ip"]:
                    self._cached_hits += 1
                    self.root.after(0, self._add_ip_row, ip, self.cache["ip"][ip])
                    done += 1
                else:
                    ip_miss.append(ip)
            if done:
                self.root.after(0, self.status_var.set, f"查询中 ... {done}/{total}（缓存命中 {self._cached_hits}）")

            for i in range(0, len(ip_miss), BATCH_SIZE):
                batch = ip_miss[i:i + BATCH_SIZE]
                try:
                    data = query_ips(batch, apikey, lang=lang, realtime=realtime)
                except Exception as ie:  # 单个批次失败不影响其它
                    text = str(ie)
                    if "没有访问接口权限" in text or "No Access to API Method" in text:
                        self._permission_error = "IP信誉（scene/ip_reputation）接口"
                    for ip in batch:
                        self.root.after(0, self._add_error_row, ip, text)
                        done += 1
                else:
                    for ip in batch:
                        item = data.get(ip)
                        if item is not None:
                            self.cache["ip"][ip] = item
                        self.root.after(0, self._add_ip_row, ip, item)
                        done += 1
                self.root.after(0, self.status_var.set,
                                f"查询中 ... {done}/{total}（缓存命中 {self._cached_hits}）")

            # ---- 域名：命中缓存直接展示，未命中批量调用 scene/dns ----
            domain_miss = []
            for d in domains:
                if d in self.cache["domain"]:
                    self._cached_hits += 1
                    self.root.after(0, self._add_domain_row, d, self.cache["domain"][d])
                    done += 1
                else:
                    domain_miss.append(d)
            if done:
                self.root.after(0, self.status_var.set,
                                f"查询中 ... {done}/{total}（缓存命中 {self._cached_hits}）")

            for i in range(0, len(domain_miss), BATCH_SIZE):
                batch = domain_miss[i:i + BATCH_SIZE]
                try:
                    _, dm = query_scene_dns(batch, apikey, lang=lang, realtime=realtime)
                except Exception as de:  # 单个批次失败不影响其它
                    text = str(de)
                    if "没有访问接口权限" in text or "No Access to API Method" in text:
                        self._permission_error = "失陷检测（scene/dns）接口"
                    for d in batch:
                        self.root.after(0, self._add_error_row, d, text)
                        done += 1
                else:
                    lower = {str(k).lower(): v for k, v in dm.items()}
                    for d in batch:
                        item = dm.get(d)
                        if item is None:
                            item = lower.get(d.lower())
                        if item is not None:
                            self.cache["domain"][d] = item
                        self.root.after(0, self._add_domain_row, d, item)
                        done += 1
                self.root.after(0, self.status_var.set,
                                f"查询中 ... {done}/{total}（缓存命中 {self._cached_hits}）")

            # ---- 文件哈希：命中缓存直接展示，未命中逐个调用 file/report ----
            file_miss = []
            for h in files:
                if h in self.cache["file"]:
                    self._cached_hits += 1
                    self.root.after(0, self._add_file_row, h, self.cache["file"][h])
                    done += 1
                else:
                    file_miss.append(h)
            if done:
                self.root.after(0, self.status_var.set,
                                f"查询中 ... {done}/{total}（缓存命中 {self._cached_hits}）")

            for h in file_miss:
                try:
                    item = query_file_report(h, apikey)
                except Exception as fe:  # 单个文件失败不影响其它
                    text = str(fe)
                    if "没有访问接口权限" in text or "No Access to API Method" in text:
                        self._permission_error = "文件信誉（file/report）接口"
                    self.root.after(0, self._add_error_row, h, text)
                else:
                    if item:
                        self.cache["file"][h] = item
                    self.root.after(0, self._add_file_row, h, item)
                done += 1
                self.root.after(0, self.status_var.set,
                                f"查询中 ... {done}/{total}（缓存命中 {self._cached_hits}）")

            save_cache(self.cache)
            self.root.after(0, self._refresh_cache_status)
            self.root.after(0, self._on_query_done, None)
        except Exception as e:  # noqa: BLE001
            save_cache(self.cache)
            self.root.after(0, self._refresh_cache_status)
            self.root.after(0, self._on_query_done, str(e))

    def clear_cache(self):
        """清空本地结果缓存，并删除缓存文件。"""
        n_ip = len(self.cache.get("ip", {}))
        n_dm = len(self.cache.get("domain", {}))
        n_fm = len(self.cache.get("file", {}))
        n = n_ip + n_dm + n_fm
        if n == 0:
            messagebox.showinfo(APP_NAME, "本地缓存已经是空的。")
            return
        if not messagebox.askyesno(
            APP_NAME,
            f"确认清空本地缓存？共 {n} 条记录（IP {n_ip} / 域名 {n_dm} / 文件 {n_fm}）。\n"
            "清空后再次查询相同资源会重新调用 API。",
        ):
            return
        self.cache = {"ip": {}, "domain": {}, "file": {}}
        clear_cache_file()
        self._cached_hits = 0
        self._refresh_cache_status()
        self.status_var.set(f"本地缓存已清空（{n} 条）")

    def _on_query_done(self, error):
        self.querying = False
        self.query_btn.configure(state="normal")
        if error:
            self.status_var.set("查询失败")
            messagebox.showerror(APP_NAME, error)
        else:
            n_ip = sum(1 for k in self.row_order if classify(k) == "ip")
            n_dm = sum(1 for k in self.row_order if classify(k) == "domain")
            n_fm = sum(1 for k in self.row_order if classify(k) == "file")
            cached = getattr(self, "_cached_hits", 0)
            self._refresh_cache_status()
            self.status_var.set(f"查询完成：共 {len(self.row_order)} 个（IP {n_ip} / 域名 {n_dm} / 文件 {n_fm}），"
                                f"本地缓存命中 {cached} 个")
            first = self.tree.get_children()
            if first:
                self.tree.selection_set(first[0])
                self.tree.focus(first[0])
            if getattr(self, "_permission_error", None):
                messagebox.showwarning(
                    APP_NAME,
                    f"{self._permission_error} 未开通权限。\n\n"
                    "当前 API Key 只能查询已授权的接口。\n"
                    "请到微步控制台「API权限」中为该 Key 开通对应接口后重试。",
                )

    # ---------------- 结果渲染 ----------------
    def _clear_results(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for i in self.domain_tree.get_children():
            self.domain_tree.delete(i)
        for i in self.file_tree.get_children():
            self.file_tree.delete(i)
        self.results = {}
        self.row_order = []
        self._permission_error = None
        self._cached_hits = 0
        self._refresh_cache_status()

    def _add_ip_row(self, ip, item):
        self._refresh_cache_status()
        if item is None:
            self._add_error_row(ip, "无数据")
            return
        basic = item.get("basic") or {}
        judgments = item.get("judgments") or []
        jt = "、".join(str(j) for j in judgments) if isinstance(judgments, list) else str(judgments)
        is_mal = item.get("is_malicious")
        verdict = "恶意" if is_mal is True else ("非恶意" if is_mal is False else "未知")
        carrier = (basic.get("carrier") or "").strip() if isinstance(basic, dict) else ""
        location = fmt_location(basic.get("location")) if isinstance(basic, dict) else ""

        self.results[ip] = {"type": "ip", "data": item}
        self.row_order.append(ip)
        tags = ("mal",) if is_mal is True else ()
        values = (ip, verdict, carrier, location, jt, item.get("permalink") or "")
        self.tree.insert("", "end", iid=f"res::{ip}", values=values, tags=tags)
        self._fit_tree_row(self.tree, ("resource", "verdict", "carrier", "location", "judgments", "permalink"), values)

    def _add_domain_row(self, domain, item):
        self._refresh_cache_status()
        if item is None:
            self._add_error_row(domain, "无数据")
            return
        judgments = item.get("judgments") or []
        jt = "、".join(str(j) for j in judgments) if isinstance(judgments, list) else str(judgments)
        verdict = verdict_from_item(item)
        confidence = CONFIDENCE_ZH.get(
            str(item.get("confidence_level", "")).lower(), item.get("confidence_level") or "-")
        severity = SEVERITY_ZH.get(
            str(item.get("severity", "")).lower(), item.get("severity") or "-")
        categories = fmt_domain_categories(item.get("categories")) or "-"
        tags_text = fmt_tags_classes(item.get("tags_classes")) or "-"

        self.results[domain] = {"type": "domain", "data": item}
        self.row_order.append(domain)
        tags = ("mal",) if verdict == "恶意" else ()
        values = (domain, verdict, confidence, severity, jt, categories, tags_text,
                  item.get("permalink") or "")
        self.domain_tree.insert("", "end", iid=f"dm::{domain}", values=values, tags=tags)
        self._fit_tree_row(
            self.domain_tree,
            ("resource", "verdict", "confidence", "severity", "judgments",
             "categories", "tags", "permalink"),
            values,
        )

    def _add_file_row(self, resource, item):
        self._refresh_cache_status()
        if not item:
            self._add_error_row(resource, "无数据")
            return
        summary = item.get("summary") if isinstance(item.get("summary"), dict) else {}
        multi = item.get("multiengines") if isinstance(item.get("multiengines"), dict) else {}
        verdict = verdict_from_file_item(item)
        level = str(summary.get("threat_level", "")).lower()
        level_text = FILE_THREAT_LEVEL_ZH.get(level, summary.get("threat_level") or "未知")
        score = summary.get("threat_score", "-")
        file_name = summary.get("file_name") or "-"
        file_type = summary.get("file_type") or "-"
        malware_type = summary.get("malware_type") or "-"
        malware_family = summary.get("malware_family") or "-"
        engines = summary.get("multi_engines") or multi.get("detect_rate") or "-"
        whitelist = "是" if summary.get("is_whitelist") is True else ("否" if summary.get("is_whitelist") is False else "-")
        permalink = item.get("permalink") or ""

        self.results[resource] = {"type": "file", "data": item}
        self.row_order.append(resource)
        tags = ("mal",) if verdict == "恶意" else ()
        values = (resource, file_hash_type(resource).upper() or "-", verdict, level_text,
                  score, file_name, file_type, malware_type, malware_family,
                  engines, whitelist, permalink)
        self.file_tree.insert("", "end", iid=f"file::{resource}", values=values, tags=tags)
        self._fit_tree_row(
            self.file_tree,
            ("resource", "hash_type", "verdict", "threat_level", "score", "file_name",
             "file_type", "malware_type", "malware_family", "multi_engines",
             "whitelist", "permalink"),
            values,
        )

    def _add_error_row(self, resource, msg):
        self._refresh_cache_status()
        full = str(msg).strip() if str(msg).strip() else "查询失败"
        short = full.splitlines()[0]
        if ("样本不存在" in short or "SAMPLE_NOT_FOUND" in short
                or "未发现报告" in short or "未收录" in short):
            status = "未收录"
        elif "没有数据" in short or "No Data" in short:
            status = "无数据"
        elif "任务进行中" in short or "In Progress" in short:
            status = "处理中"
        else:
            status = "查询失败"
        kind = classify(resource)
        self.results[resource] = {"type": kind, "error": msg}
        self.row_order.append(resource)
        if kind == "ip":
            values = (resource, status, "", "", "-", short)
            self.tree.insert("", "end", iid=f"res::{resource}", values=values)
            self._fit_tree_row(
                self.tree,
                ("resource", "verdict", "carrier", "location", "judgments", "permalink"),
                values,
            )
        elif kind == "file":
            values = (resource, file_hash_type(resource).upper() or "-", status,
                      "-", "-", "-", "-", "-", "-", "-", "-", short)
            self.file_tree.insert("", "end", iid=f"file::{resource}::err", values=values)
            self._fit_tree_row(
                self.file_tree,
                ("resource", "hash_type", "verdict", "threat_level", "score", "file_name",
                 "file_type", "malware_type", "malware_family", "multi_engines",
                 "whitelist", "permalink"),
                values,
            )
        else:
            values = (resource, status, "-", "-", "-", "-", "-", short)
            self.domain_tree.insert("", "end", iid=f"dm::{resource}::err", values=values)
            self._fit_tree_row(
                self.domain_tree,
                ("resource", "verdict", "confidence", "severity", "judgments",
                 "categories", "tags", "permalink"),
                values,
            )

    def _open_permalink(self, resource):
        r = self.results.get(resource, {})
        url = (r.get("data") or {}).get("permalink") if isinstance(r.get("data"), dict) else None
        if url and str(url).startswith("http"):
            webbrowser.open(url)

    def on_resource_double_click(self, _event):
        sel = self.tree.selection()
        if sel:
            self._open_permalink(self.tree.item(sel[0], "values")[0])

    def on_domain_double_click(self, _event):
        sel = self.domain_tree.selection()
        if sel:
            self._open_permalink(self.domain_tree.item(sel[0], "values")[0])

    def on_file_double_click(self, _event):
        sel = self.file_tree.selection()
        if sel:
            self._open_permalink(self.file_tree.item(sel[0], "values")[0])

    # ---------------- 导出 ----------------
    def export_csv(self):
        if not self.results:
            messagebox.showinfo(APP_NAME, "当前没有可导出的结果。")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV 文件", "*.csv")],
            initialfile=f"ip_results_{datetime.now():%Y%m%d_%H%M%S}.csv")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow(["IP", "判定", "运营商", "地理位置", "威胁判定", "详情链接"])
                for row in self.tree.get_children():
                    w.writerow(self.tree.item(row, "values"))
            self.status_var.set(f"已导出：{path}")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"导出失败：{e}")

    def export_domains_csv(self):
        rows = self.domain_tree.get_children()
        if not rows:
            messagebox.showinfo(APP_NAME, "当前没有域名结果可导出。")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV 文件", "*.csv")],
            initialfile=f"domain_results_{datetime.now():%Y%m%d_%H%M%S}.csv")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow(["域名", "判定", "可信度", "严重级别", "威胁判定",
                            "域名分类", "标签", "详情链接"])
                for row in rows:
                    w.writerow(self.domain_tree.item(row, "values"))
            self.status_var.set(f"已导出：{path}")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"导出失败：{e}")

    def export_files_csv(self):
        rows = self.file_tree.get_children()
        if not rows:
            messagebox.showinfo(APP_NAME, "当前没有文件信誉结果可导出。")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV 文件", "*.csv")],
            initialfile=f"file_results_{datetime.now():%Y%m%d_%H%M%S}.csv")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow(["哈希", "类型", "判定", "威胁等级", "评分", "文件名", "文件类型",
                            "恶意类型", "家族", "引擎检出", "白名单", "详情链接"])
                for row in rows:
                    w.writerow(self.file_tree.item(row, "values"))
            self.status_var.set(f"已导出：{path}")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"导出失败：{e}")

    def export_json(self):
        if not self.results:
            messagebox.showinfo(APP_NAME, "当前没有可导出的结果。")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON 文件", "*.json")],
            initialfile=f"threatbook_{datetime.now():%Y%m%d_%H%M%S}.json")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.results, f, ensure_ascii=False, indent=2)
            self.status_var.set(f"已导出：{path}")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"导出失败：{e}")


def main():
    _set_app_user_model_id()
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()





