#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
微步在线 IP / 域名 混合查询工具（图形界面版）

功能:
    - 默认不预置 API Key，可修改 / 保存 API Key
    - 批量混合查询 IP 与域名（自动识别类型）
    - IP:  调用 IP 信誉接口，展示 basic / is_malicious / judgments / tags_classes / permalink
    - 域名: 调用域名分析接口，重点展示 samples（相关样本）
    - IP样本信誉 / 域名样本信誉 双视图
    - 恶意结果红色标注，非恶意不着色
    - 支持浅色 / 暗色模式切换
    - 导出 CSV / 样本 CSV / JSON
    - 双击结果行打开情报详情页
"""

import csv
import ipaddress
import json
import os
import re
import sys
import threading
import webbrowser
from datetime import datetime

import requests

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.scrolledtext import ScrolledText

IP_API_URL = "https://api.threatbook.cn/v3/scene/ip_reputation"
DOMAIN_API_URL = "https://api.threatbook.cn/v3/domain/query"

BATCH_SIZE = 100          # IP 接口单次上限
APP_NAME = "微步IP/域名信誉查询API调用"
VERSION = "2.3.3"

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
    """从本地文件读取缓存，返回 {"ip": {...}, "domain": {...}}。"""
    empty = {"ip": {}, "domain": {}}
    try:
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                ip = data.get("ip") if isinstance(data.get("ip"), dict) else {}
                dm = data.get("domain") if isinstance(data.get("domain"), dict) else {}
                return {"ip": ip, "domain": dm}
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
def classify(token):
    """返回 'ip' 或 'domain'。"""
    try:
        ipaddress.ip_address(token)
        return "ip"
    except ValueError:
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
        key = tok if kind == "ip" else normalize_domain(tok)
        if not key or key in seen:
            continue
        seen.add(key)
        items.append((key, kind))
    return items


# ----------------------------------------------------------------------------
# 接口调用
# ----------------------------------------------------------------------------
def _raise_api_error(payload, endpoint):
    code = payload.get("response_code")
    if code == 0:
        return
    msg = payload.get("verbose_msg")
    hint = ""
    text = str(msg)
    if code == -1 and ("Invalid Access IP" in text or "访问IP" in text):
        hint = "\n\n请到微步控制台「我的KEY」中，把当前出口 IP 加入白名单。"
    elif code == -1 and ("No Access to API Method" in text or "没有访问接口权限" in text):
        hint = "\n\n当前 API Key 未开通该接口权限，请到微步控制台「API权限」中申请/开通对应接口。"
    elif code == -4:
        hint = "\n\n已触发限速或超出配额，请稍后重试或检查接口额度。"
    raise RuntimeError(f"[{endpoint}] {msg}{hint}（response_code={code}）")


def query_ips(ips, apikey, lang="zh", realtime=False, timeout=30):
    """批量查询 IP（<=100），返回 {ip: result}。"""
    params = {
        "resource": ",".join(ips),
        "apikey": apikey,
        "lang": lang,
        "realtime_verdict": "true" if realtime else "false",
    }
    resp = requests.get(IP_API_URL, params=params, timeout=timeout)
    resp.raise_for_status()
    payload = resp.json()
    _raise_api_error(payload, "IP信誉")
    data = payload.get("data", {}) or {}
    if isinstance(data.get("ips"), dict):
        return data["ips"]
    return data


def query_domain(domain, apikey, lang="zh", timeout=30):
    """查询单个域名（域名接口不支持批量）。"""
    params = {"resource": domain, "apikey": apikey, "lang": lang}
    resp = requests.get(DOMAIN_API_URL, params=params, timeout=timeout)
    resp.raise_for_status()
    payload = resp.json()
    _raise_api_error(payload, "域名分析")
    data = payload.get("data", {}) or {}
    if domain in data:
        return data[domain]
    for k, v in data.items():
        if str(k).lower() == domain.lower():
            return v
    if len(data) == 1:
        return next(iter(data.values()))
    return None


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


def parse_samples(data):
    """从域名结果中提取样本列表，返回标准化 dict 列表。"""
    samples = data.get("samples") if isinstance(data, dict) else None
    if not isinstance(samples, list):
        return []
    out = []
    for s in samples:
        if not isinstance(s, dict):
            continue
        out.append({
            "sha256": s.get("sha256", ""),
            "scan_time": s.get("scan_time", ""),
            "ratio": s.get("ratio", ""),
            "malware_type": s.get("malware_type", ""),
            "malware_family": s.get("malware_family", ""),
            "threat_level": THREAT_LEVEL_ZH.get(str(s.get("threat_level", "")).lower(),
                                                s.get("threat_level", "")),
        })
    return out


# ----------------------------------------------------------------------------
# 主界面
# ----------------------------------------------------------------------------
class App:
    def __init__(self, root):
        self.root = root
        self.cfg = load_config()
        self.results = {}     # 资源 -> {"type":..., "data":...}
        self.row_order = []
        self.samples = []     # [{resource, sha256, ...}]
        self.cache = load_cache()   # 本地结果缓存 {"ip": {...}, "domain": {...}}
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
        for tv in (self.tree, self.sample_tree):
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
        ttk.Checkbutton(top, text="仅当前有效情报（不勾选=含历史过期情报，仅对 IP 生效）",
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
        mid = ttk.LabelFrame(self.root, text="批量输入（IP 与 域名 可混合，每行一个或用逗号/空格/分号分隔）", padding=10)
        mid.pack(fill="both", expand=False, padx=12, pady=6)

        self.input_text = ScrolledText(mid, height=6, font=("Consolas", 10), wrap="word")
        self.input_text.pack(fill="both", expand=True)

        btns = ttk.Frame(mid)
        btns.pack(fill="x", pady=(8, 0))
        self.query_btn = ttk.Button(btns, text="开始查询", command=self.on_query)
        self.query_btn.pack(side="left")
        ttk.Button(btns, text="清空输入", command=lambda: self.input_text.delete("1.0", "end")).pack(side="left", padx=6)
        ttk.Button(btns, text="导出 IP 结果 CSV", command=self.export_csv).pack(side="left", padx=6)
        ttk.Button(btns, text="导出域名样本 CSV", command=self.export_samples_csv).pack(side="left", padx=6)
        ttk.Button(btns, text="导出 JSON", command=self.export_json).pack(side="left", padx=6)
        self.count_label = ttk.Label(btns, text="待查询：0 个（IP 0 / 域名 0）")
        self.count_label.pack(side="right")
        self.input_text.bind("<KeyRelease>", self._update_count)

        # ---------- 结果区（上下分栏） ----------
        pane = ttk.Panedwindow(self.root, orient="vertical")
        pane.pack(fill="both", expand=True, padx=12, pady=(6, 4))

        # 上：IP样本信誉（仅展示 IP 查询结果）
        res_frame = ttk.LabelFrame(pane, text="IP样本信誉（仅展示 IP 查询结果，双击打开情报详情页）", padding=8)
        pane.add(res_frame, weight=2)

        res_cols = ("resource", "verdict", "carrier", "location", "judgments", "permalink")
        res_heads = ("IP", "判定", "运营商", "地理位置", "威胁判定", "详情链接")
        res_widths = (180, 70, 150, 230, 260, 300)
        res_align = {"resource": "w", "verdict": "center", "carrier": "w",
                     "location": "w", "judgments": "w", "permalink": "w"}

        self.tree = ttk.Treeview(res_frame, columns=res_cols, show="headings", selectmode="browse")
        for c, h, w in zip(res_cols, res_heads, res_widths):
            self.tree.heading(c, text=h, anchor=res_align[c])
            self.tree.column(c, width=w, anchor=res_align[c],
                             stretch=(c in ("location", "judgments", "permalink")))

        rvs = ttk.Scrollbar(res_frame, orient="vertical", command=self.tree.yview)
        rhs = ttk.Scrollbar(res_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=rvs.set, xscrollcommand=rhs.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        rvs.grid(row=0, column=1, sticky="ns")
        rhs.grid(row=1, column=0, sticky="ew")
        res_frame.rowconfigure(0, weight=1)
        res_frame.columnconfigure(0, weight=1)
        self.tree.bind("<Double-1>", self.on_resource_double_click)

        # 下：域名样本信誉（仅展示域名样本查询结果）
        smp_frame = ttk.LabelFrame(pane, text="域名样本信誉（仅展示域名样本查询结果，双击打开域名情报详情页）", padding=8)
        pane.add(smp_frame, weight=3)

        smp_cols = ("resource", "verdict", "judgments", "sha256", "scan_time", "ratio",
                    "malware_type", "malware_family", "threat_level")
        smp_heads = ("域名", "判定", "威胁判定", "SHA256", "检测时间", "检出率",
                     "恶意类型", "恶意家族", "威胁等级")
        smp_widths = (170, 70, 200, 470, 140, 70, 130, 130, 80)
        smp_align = {"resource": "w", "verdict": "center", "judgments": "w",
                     "sha256": "w", "scan_time": "center", "ratio": "center",
                     "malware_type": "w", "malware_family": "w", "threat_level": "center"}

        self.sample_tree = ttk.Treeview(smp_frame, columns=smp_cols, show="headings", selectmode="browse")
        for c, h, w in zip(smp_cols, smp_heads, smp_widths):
            self.sample_tree.heading(c, text=h, anchor=smp_align[c])
            self.sample_tree.column(c, width=w, anchor=smp_align[c], stretch=(c in ("sha256",)))

        svs = ttk.Scrollbar(smp_frame, orient="vertical", command=self.sample_tree.yview)
        shs = ttk.Scrollbar(smp_frame, orient="horizontal", command=self.sample_tree.xview)
        self.sample_tree.configure(yscrollcommand=svs.set, xscrollcommand=shs.set)
        self.sample_tree.grid(row=0, column=0, sticky="nsew")
        svs.grid(row=0, column=1, sticky="ns")
        shs.grid(row=1, column=0, sticky="ew")
        smp_frame.rowconfigure(0, weight=1)
        smp_frame.columnconfigure(0, weight=1)
        self.sample_tree.bind("<Double-1>", self.on_sample_double_click)

        # 底部状态栏：查询状态 + 本地缓存统计 + 清空缓存 + 作者署名
        self.status_var = tk.StringVar(value="就绪")
        self.cache_info_var = tk.StringVar(value="本地缓存：IP 0 / 域名 0 ｜ 本次命中缓存：0")
        status_bar = ttk.Frame(self.root)
        status_bar.pack(fill="x", side="bottom", before=pane)
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
        n_ip = len(ip) if isinstance(ip, dict) else 0
        n_dm = len(dm) if isinstance(dm, dict) else 0
        hits = getattr(self, "_cached_hits", 0)
        self.cache_info_var.set(f"本地缓存：IP {n_ip} / 域名 {n_dm} ｜ 本次命中缓存：{hits}")

    def _update_count(self, _event=None):
        items = parse_input(self.input_text.get("1.0", "end"))
        n_ip = sum(1 for _, k in items if k == "ip")
        n_dm = len(items) - n_ip
        self.count_label.configure(text=f"待查询：{len(items)} 个（IP {n_ip} / 域名 {n_dm}）")

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
            messagebox.showwarning(APP_NAME, "请输入要查询的 IP 或域名。")
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
                data = query_ips(batch, apikey, lang=lang, realtime=realtime)
                for ip in batch:
                    item = data.get(ip)
                    if item is not None:
                        self.cache["ip"][ip] = item
                    self.root.after(0, self._add_ip_row, ip, item)
                    done += 1
                self.root.after(0, self.status_var.set,
                                f"查询中 ... {done}/{total}（缓存命中 {self._cached_hits}）")

            # ---- 域名：逐个查询，命中缓存直接展示 ----
            for d in domains:
                if d in self.cache["domain"]:
                    self._cached_hits += 1
                    self.root.after(0, self._add_domain_row, d, self.cache["domain"][d])
                else:
                    try:
                        item = query_domain(d, apikey, lang=lang)
                        if item is not None:
                            self.cache["domain"][d] = item
                        self.root.after(0, self._add_domain_row, d, item)
                    except Exception as de:  # 单个域名失败不影响其它
                        text = str(de)
                        if "没有访问接口权限" in text or "No Access to API Method" in text:
                            self._permission_error = "域名分析接口"
                        self.root.after(0, self._add_error_row, d, text)
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
        n = n_ip + n_dm
        if n == 0:
            messagebox.showinfo(APP_NAME, "本地缓存已经是空的。")
            return
        if not messagebox.askyesno(
            APP_NAME,
            f"确认清空本地缓存？共 {n} 条记录（IP {n_ip} / 域名 {n_dm}）。\n"
            "清空后再次查询相同资源会重新调用 API。",
        ):
            return
        self.cache = {"ip": {}, "domain": {}}
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
            n_dm = len(self.row_order) - n_ip
            cached = getattr(self, "_cached_hits", 0)
            self._refresh_cache_status()
            self.status_var.set(f"查询完成：共 {len(self.row_order)} 个（IP {n_ip} / 域名 {n_dm}），"
                                f"样本 {len(self.samples)} 条，本地缓存命中 {cached} 个")
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
        for i in self.sample_tree.get_children():
            self.sample_tree.delete(i)
        self.results = {}
        self.row_order = []
        self.samples = []
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
        self.tree.insert("", "end", iid=f"res::{ip}",
                         values=(ip, verdict, carrier, location, jt, item.get("permalink") or ""),
                         tags=tags)

    def _add_domain_row(self, domain, item):
        self._refresh_cache_status()
        if item is None:
            self._add_error_row(domain, "无数据")
            return
        judgments = item.get("judgments") or []
        jt = "、".join(str(j) for j in judgments) if isinstance(judgments, list) else str(judgments)
        verdict = verdict_from_judgments(judgments)

        samples = parse_samples(item)
        self.results[domain] = {"type": "domain", "data": item}
        self.row_order.append(domain)

        if not samples:
            self.sample_tree.insert("", "end", iid=f"smp::{domain}::0",
                                    values=(domain, verdict, jt, "-", "-", "-", "-", "-", "-"))
            return
        for i, s in enumerate(samples):
            row = {"resource": domain, **s}
            self.samples.append(row)
            level = s["threat_level"]
            tags = ("mal",) if level == "恶意" else ()
            self.sample_tree.insert("", "end", iid=f"smp::{domain}::{i}",
                                    values=(domain, verdict, jt, s["sha256"], s["scan_time"],
                                            s["ratio"], s["malware_type"], s["malware_family"],
                                            s["threat_level"]),
                                    tags=tags)

    def _add_error_row(self, resource, msg):
        self._refresh_cache_status()
        short = str(msg).splitlines()[0] if str(msg).strip() else "查询失败"
        self.results[resource] = {"type": classify(resource), "error": msg}
        self.row_order.append(resource)
        if classify(resource) == "ip":
            self.tree.insert("", "end", iid=f"res::{resource}",
                             values=(resource, "查询失败", "", "", short, ""))
        else:
            self.sample_tree.insert("", "end", iid=f"smp::{resource}::err",
                                    values=(resource, "查询失败", short,
                                            "-", "-", "-", "-", "-", "-"))

    def _open_permalink(self, resource):
        r = self.results.get(resource, {})
        url = (r.get("data") or {}).get("permalink") if isinstance(r.get("data"), dict) else None
        if url and str(url).startswith("http"):
            webbrowser.open(url)

    def on_resource_double_click(self, _event):
        sel = self.tree.selection()
        if sel:
            self._open_permalink(self.tree.item(sel[0], "values")[0])

    def on_sample_double_click(self, _event):
        sel = self.sample_tree.selection()
        if sel:
            self._open_permalink(self.sample_tree.item(sel[0], "values")[0])

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

    def export_samples_csv(self):
        rows = self.sample_tree.get_children()
        if not rows:
            messagebox.showinfo(APP_NAME, "当前没有域名样本数据可导出。")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV 文件", "*.csv")],
            initialfile=f"domain_samples_{datetime.now():%Y%m%d_%H%M%S}.csv")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow(["域名", "判定", "威胁判定", "SHA256", "检测时间",
                            "检出率", "恶意类型", "恶意家族", "威胁等级"])
                for row in rows:
                    w.writerow(self.sample_tree.item(row, "values"))
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





