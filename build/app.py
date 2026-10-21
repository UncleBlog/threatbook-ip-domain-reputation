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
    - 本地缓存查看：按 IP / 域名 / 文件分类列出所有已缓存记录
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
from collections import deque
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
IP_RATE_LIMIT_PER_MINUTE = 60   # /v3/scene/ip_reputation 官方频次限制：60 次/分钟
IP_RATE_LIMIT_WINDOW_SECONDS = 60
APP_NAME = "微步IP/域名/文件信誉查询API调用"
VERSION = "2.6.4"

CONFIG_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "ThreatBookIPReputation")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
CACHE_FILE = os.path.join(CONFIG_DIR, "cache.json")


def resource_path(name):
    """兼容源码运行与 PyInstaller 打包后的资源定位。"""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


APP_ICON_ICO = resource_path("app.ico")
APP_ICON_PNG = resource_path("app.png")
_ICON_HANDLES = []


def _set_native_window_icon(window):
    """用 Win32 原生接口同步标题栏、窗口类和任务栏图标，避免回退到 Tk 默认羽毛图标。"""
    if sys.platform != "win32" or not os.path.exists(APP_ICON_ICO):
        return
    hwnd = _get_toplevel_hwnd(window)
    if not hwnd:
        return
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        user32.LoadImageW.restype = wintypes.HANDLE
        user32.LoadImageW.argtypes = [
            wintypes.HINSTANCE,
            wintypes.LPCWSTR,
            wintypes.UINT,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.UINT,
        ]
        user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, ctypes.c_void_p, ctypes.c_void_p]
        user32.SendMessageW.restype = ctypes.c_void_p

        image_icon = 1
        lr_loadfromfile = 0x00000010
        wm_seticon = 0x0080
        icon_small = 0
        icon_big = 1

        # 同时准备 16/32/48 尺寸；Windows 在高 DPI 下会按需选择，不再回退到 Python/Tk 图标。
        handles = []
        hicon_small = user32.LoadImageW(None, APP_ICON_ICO, image_icon, 16, 16, lr_loadfromfile)
        hicon_big = (
            user32.LoadImageW(None, APP_ICON_ICO, image_icon, 32, 32, lr_loadfromfile)
            or user32.LoadImageW(None, APP_ICON_ICO, image_icon, 48, 48, lr_loadfromfile)
            or user32.LoadImageW(None, APP_ICON_ICO, image_icon, 0, 0, lr_loadfromfile)
        )
        for handle in (hicon_small, hicon_big):
            if handle:
                handles.append(handle)
                _ICON_HANDLES.append(handle)

        if hicon_small:
            user32.SendMessageW(hwnd, wm_seticon, ctypes.c_void_p(icon_small), hicon_small)
        if hicon_big:
            user32.SendMessageW(hwnd, wm_seticon, ctypes.c_void_p(icon_big), hicon_big)

        # 同步窗口类图标，覆盖部分 Windows 版本的任务栏/Alt+Tab 图标缓存。
        try:
            if hasattr(user32, "SetClassLongPtrW"):
                set_class_icon = user32.SetClassLongPtrW
                set_class_icon.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_void_p]
                set_class_icon.restype = ctypes.c_void_p
            else:
                set_class_icon = user32.SetClassLongW
                set_class_icon.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_void_p]
                set_class_icon.restype = ctypes.c_void_p
            gclp_hicon = -14
            gclp_hiconsm = -34
            if hicon_small:
                set_class_icon(hwnd, gclp_hiconsm, hicon_small)
            if hicon_big:
                set_class_icon(hwnd, gclp_hicon, hicon_big)
        except Exception:
            pass
    except Exception:
        pass


def _set_app_user_model_id():
    """Windows: 设置 AppUserModelID，确保任务栏/开始菜单使用本程序图标而非 Python 默认图标。"""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "Uncledavid.ThreatBook.Query")
    except Exception:
        pass

# 默认不预置 API Key，需由用户在界面中填写并保存
DEFAULT_API_KEY = ""


def _enable_high_dpi_awareness():
    """在创建 Tk 窗口前启用 Per-Monitor DPI V2，避免字体发虚。"""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        try:
            # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
            ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
            return
        except Exception:
            pass
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)  # PROCESS_PER_MONITOR_DPI_AWARE
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass
    except Exception:
        pass


def _pick_font(root, candidates, fallback):
    """优先选择系统内置的高质量 UI 字体，保证中文和高分屏显示清晰。"""
    try:
        installed = set(tkfont.families(root))
        for name in candidates:
            if name in installed:
                return name
    except Exception:
        pass
    return fallback


def _setup_tk_fonts(root):
    """按系统 DPI 调整 Tk 字体缩放，并把默认字体统一为高清 UI 字体。"""
    family = _pick_font(
        root,
        ("Microsoft YaHei UI", "Segoe UI Variable Text", "Microsoft YaHei", "Segoe UI"),
        "Microsoft YaHei UI",
    )
    try:
        dpi = float(root.winfo_fpixels("1i"))
        if dpi > 0:
            root.tk.call("tk", "scaling", dpi / 72.0)
    except Exception:
        pass
    for font_name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont"):
        try:
            tkfont.nametofont(font_name).configure(family=family, size=10)
        except Exception:
            pass
    return family


def _get_toplevel_hwnd(window):
    """获取 Tk 顶层窗口对应的原生 HWND。"""
    if sys.platform != "win32":
        return None
    try:
        import ctypes
        window.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
        return hwnd or window.winfo_id()
    except Exception:
        return None


def _center_window(window, width, height, min_width=None, min_height=None):
    """按屏幕可用区域设置窗口大小并居中，避免默认窗口过小或意外全屏。"""
    try:
        window.update_idletasks()
        screen_w = int(window.winfo_screenwidth())
        screen_h = int(window.winfo_screenheight())
        try:
            dpi_scale = max(1.0, float(window.winfo_fpixels("1i")) / 96.0)
        except Exception:
            dpi_scale = 1.0

        # Tk 的 geometry 单位在高 DPI 机器上会被系统缩放；按 DPI 换算后，
        # 参数中的宽高更接近用户看到的实际窗口尺寸。
        width_cfg = int(int(width) * dpi_scale)
        height_cfg = int(int(height) * dpi_scale)
        safe_w = max(760, screen_w - int(100 * dpi_scale))
        safe_h = max(540, screen_h - int(120 * dpi_scale))
        width_cfg = min(width_cfg, safe_w)
        height_cfg = min(height_cfg, safe_h)
        if min_width is not None:
            width_cfg = max(width_cfg, min(int(int(min_width) * dpi_scale), safe_w))
        if min_height is not None:
            height_cfg = max(height_cfg, min(int(int(min_height) * dpi_scale), safe_h))
        x = max(0, (screen_w - width_cfg) // 2)
        y = max(0, (screen_h - height_cfg) // 2)
        window.geometry(f"{width_cfg}x{height_cfg}+{x}+{y}")
        if min_width is not None and min_height is not None:
            window.minsize(
                min(int(int(min_width) * dpi_scale), safe_w),
                min(int(int(min_height) * dpi_scale), safe_h),
            )
    except Exception:
        pass


def _set_acrylic_fallback(hwnd, dark, enabled=True):
    """Win10/部分 Win11 环境下的 Acrylic 回退实现。"""
    try:
        import ctypes
        from ctypes import wintypes

        class ACCENTPOLICY(ctypes.Structure):
            _fields_ = [
                ("AccentState", ctypes.c_int),
                ("AccentFlags", ctypes.c_int),
                ("GradientColor", ctypes.c_uint),
                ("AnimationId", ctypes.c_int),
            ]

        class WINCOMPATTRDATA(ctypes.Structure):
            _fields_ = [
                ("Attribute", ctypes.c_int),
                ("Data", ctypes.c_void_p),
                ("SizeOfData", ctypes.c_size_t),
            ]

        accent = ACCENTPOLICY()
        accent.AccentState = 4 if enabled else 0  # ACRYLIC / DISABLED
        accent.AccentFlags = 2 if enabled else 0
        accent.GradientColor = (0xCC1F1F1F if dark else 0xCCF3F3F3) if enabled else 0
        data = WINCOMPATTRDATA()
        data.Attribute = 19  # WCA_ACCENT_POLICY
        data.Data = ctypes.cast(ctypes.pointer(accent), ctypes.c_void_p)
        data.SizeOfData = ctypes.sizeof(accent)
        ctypes.windll.user32.SetWindowCompositionAttribute(hwnd, ctypes.byref(data))
    except Exception:
        pass


def _set_dwm_backdrop(hwnd, dark=False, enabled=True):
    """Enable or temporarily disable the Mica/Acrylic backdrop."""
    if not hwnd:
        return
    applied = False
    try:
        import ctypes

        # DWMWA_SYSTEMBACKDROP_TYPE: 1=None, 3=Acrylic
        backdrop = ctypes.c_int(3 if enabled else 1)
        applied = ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd, 38, ctypes.byref(backdrop), ctypes.sizeof(backdrop)
        ) == 0
    except Exception:
        applied = False

    if enabled and not applied:
        _set_acrylic_fallback(hwnd, dark, True)
    elif not enabled:
        _set_acrylic_fallback(hwnd, dark, False)


def _apply_windows_material(window, dark=False):
    """为窗口应用 Windows 11 圆角、暗色标题栏与 Acrylic/Mica 背景。"""
    hwnd = _get_toplevel_hwnd(window)
    if not hwnd:
        return
    try:
        window._tb_hwnd = hwnd
    except Exception:
        pass
    try:
        import ctypes

        value = ctypes.c_int(1 if dark else 0)
        # DWMWA_USE_IMMERSIVE_DARK_MODE（新版本 20，旧版本 19）
        for attr in (20, 19):
            try:
                if ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, attr, ctypes.byref(value), ctypes.sizeof(value)
                ) == 0:
                    break
            except Exception:
                pass

        # DWMWA_WINDOW_CORNER_PREFERENCE = DWMWCP_ROUND
        try:
            corner = ctypes.c_int(2)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, 33, ctypes.byref(corner), ctypes.sizeof(corner)
            )
        except Exception:
            pass

        # 标题栏与边框使用当前主题色，保持深色模式整体一致。
        try:
            caption_color = 0x001F1F1F if dark else 0x00F3F3F3
            border_color = 0x003F3F3F if dark else 0x00D0D3D7
            caption = ctypes.c_uint(caption_color)
            border = ctypes.c_uint(border_color)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, 35, ctypes.byref(caption), ctypes.sizeof(caption)
            )
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, 34, ctypes.byref(border), ctypes.sizeof(border)
            )
        except Exception:
            pass

        _set_dwm_backdrop(hwnd, dark, enabled=True)
    except Exception:
        pass

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

# 浅色 / 暗色主题调色板（Windows 11 Acrylic / Mica 风格，保证底色与字体颜色对比明显）
THEMES = {
    "light": {
        "root_bg": "#f3f3f3",
        "panel_bg": "#fbfbfb",
        "text_bg": "#ffffff",
        "text_fg": "#1b1b1b",
        "field_bg": "#ffffff",
        "field_fg": "#1b1b1b",
        "row_bg": "#ffffff",
        "row_fg": "#1b1b1b",
        "row_alt": "#f6f7f9",
        "heading_bg": "#ebedf0",
        "heading_fg": "#1b1b1b",
        "select_bg": "#cfe4ff",
        "select_fg": "#003a70",
        "malice_fg": "#c42b1c",
        "border": "#d0d3d7",
        "insert": "#1b1b1b",
    },
    "dark": {
        "root_bg": "#202020",
        "panel_bg": "#2b2b2b",
        "text_bg": "#1f1f1f",
        "text_fg": "#ffffff",
        "field_bg": "#323232",
        "field_fg": "#ffffff",
        "row_bg": "#262626",
        "row_fg": "#ffffff",
        "row_alt": "#2d2d2d",
        "heading_bg": "#343434",
        "heading_fg": "#ffffff",
        "select_bg": "#4cc2ff",
        "select_fg": "#000000",
        "malice_fg": "#ff99a4",
        "border": "#3f3f3f",
        "insert": "#ffffff",
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


class _SlidingWindowRateLimiter:
    """线程安全的滑动窗口限速器（按 HTTP 请求次数计时）。"""
    def __init__(self, max_calls, window_seconds):
        self._max_calls = max_calls
        self._window = window_seconds
        self._times = deque()
        self._lock = threading.Lock()

    def acquire(self):
        while True:
            with self._lock:
                now = time.monotonic()
                while self._times and now - self._times[0] >= self._window:
                    self._times.popleft()
                if len(self._times) < self._max_calls:
                    self._times.append(now)
                    return
                wait = self._window - (now - self._times[0])
            time.sleep(min(max(wait, 0.05), self._window))


_IP_RATE_LIMITER = _SlidingWindowRateLimiter(
    IP_RATE_LIMIT_PER_MINUTE, IP_RATE_LIMIT_WINDOW_SECONDS
)


def _request_json(url, params, endpoint, timeout=30):
    """请求微步接口并解析 JSON；临时网络异常自动重试，最终返回中文错误。"""
    last_exc = None
    for attempt in range(1, NETWORK_MAX_ATTEMPTS + 1):
        if url == IP_API_URL:
            _IP_RATE_LIMITER.acquire()
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
        self.cache_window = None
        self.cache_trees = {}
        self.font_family = _pick_font(
            root,
            ("Microsoft YaHei UI", "Segoe UI Variable Text", "Microsoft YaHei", "Segoe UI"),
            "Microsoft YaHei UI",
        )

        # 先隐藏主窗口，等尺寸、内容与主题全部就绪后再显示：
        # Tk 的 Toplevel/Root 创建时会先以默认小尺寸映射到父窗口左上角，
        # 若先显示再居中，启动瞬间就会在屏幕左上角闪出一个小窗。
        self._root_hidden_on_start = False
        try:
            root.withdraw()
            self._root_hidden_on_start = True
        except Exception:
            pass

        root.title(f"{APP_NAME} v{VERSION}")
        _center_window(root, 1500, 860, min_width=1100, min_height=700)
        self._set_icon()

        try:
            self._build_style()
            self._build_widgets()
            self._apply_theme()
        finally:
            try:
                self._install_resize_guard(root)
            except Exception:
                pass
            # 尺寸、内容、图标与毛玻璃全部就绪后才真正显示，避免可见的跳变。
            if self._root_hidden_on_start:
                try:
                    root.deiconify()
                    root.lift()
                except Exception:
                    pass

    def _build_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Treeview", rowheight=30, font=(self.font_family, 10),
                        borderwidth=0, relief="flat")
        style.configure("Treeview.Heading", font=(self.font_family, 10, "bold"),
                        padding=(6, 8))
        style.map("Treeview.Heading", relief=[("active", "flat")])
        style.configure("TButton", font=(self.font_family, 10), padding=(12, 7))
        style.configure("Small.TButton", font=(self.font_family, 9), padding=(8, 4))
        style.configure("TLabel", font=(self.font_family, 10))
        style.configure("TCheckbutton", font=(self.font_family, 10))
        style.configure("TRadiobutton", font=(self.font_family, 10))
        style.configure("TLabelframe.Label", font=(self.font_family, 10, "bold"))
        self._tree_font = tkfont.Font(family=self.font_family, size=10)

    def _header_min_width(self, text, fallback=60):
        """保证表头文字有足够宽度，避免窗口缩放后标题重叠或被挤没。"""
        try:
            return max(int(fallback), self._tree_font.measure(str(text)) + 28)
        except Exception:
            return int(fallback)

    def _configure_tree_columns(self, tree, columns, heads, widths, align=None):
        """初始化 Treeview 列，并记录窗口缩放时使用的比例和表头最小宽度。"""
        align = align or {}
        columns = tuple(columns)
        heads = tuple(heads)
        min_widths = tuple(self._header_min_width(head, 52) for head in heads)
        base_widths = tuple(max(int(width), min_width) for width, min_width in zip(widths, min_widths))
        tree._autofit_meta = {
            "columns": columns,
            "bases": base_widths,
            "mins": min_widths,
        }
        for column, head, width, min_width in zip(columns, heads, base_widths, min_widths):
            anchor = align.get(column, "w")
            tree.heading(column, text=head, anchor=anchor)
            tree.column(column, width=width, minwidth=min_width, anchor=anchor, stretch=False)
        tree.bind("<Configure>", lambda _event, tv=tree: self._autofit_tree_columns(tv), add="+")
        try:
            tree.after_idle(lambda: self._autofit_tree_columns(tree))
        except Exception:
            pass

    def _autofit_tree_columns(self, tree):
        """按窗口可用宽度等比分配列宽；窄窗口先保表头最小宽度，超宽时自动均分扩展。"""
        try:
            if not tree.winfo_exists():
                return
            meta = getattr(tree, "_autofit_meta", None)
            if not meta:
                return
            columns = meta["columns"]
            bases = meta["bases"]
            mins = meta["mins"]
            available = max(1, int(tree.winfo_width()) - 4)
            min_total = sum(mins)
            if available <= min_total:
                widths = list(mins)
            else:
                extra = available - min_total
                weights = [max(1, base - min_width) for base, min_width in zip(bases, mins)]
                weight_total = sum(weights) or 1
                widths = [min_width + int(extra * weight / weight_total)
                          for min_width, weight in zip(mins, weights)]
                remainder = available - sum(widths)
                if remainder:
                    widths[-1] += remainder
            current = [int(float(tree.column(column, "width"))) for column in columns]
            if current == widths:
                return
            for column, width, min_width in zip(columns, widths, mins):
                tree.column(column, width=width, minwidth=min_width, stretch=False)
        except Exception:
            pass

    def _fit_tree_row(self, tree, columns, values):
        """列宽由窗口自适应统一管理，避免逐行加宽后表头互相覆盖。"""
        return

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
                        insertcolor=t["field_fg"], bordercolor=t["border"],
                        lightcolor=t["field_bg"], darkcolor=t["field_bg"], padding=(8, 6))
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
        win = getattr(self, "cache_window", None)
        if win is not None and win.winfo_exists():
            try:
                win.configure(bg=t["root_bg"])
            except Exception:
                pass
        for tv in getattr(self, "cache_trees", {}).values():
            try:
                if tv.winfo_exists():
                    tv.tag_configure("mal", foreground=t["malice_fg"])
            except Exception:
                pass
        _apply_windows_material(self.root, bool(self.dark_var.get()))
        try:
            self.root.after(120, lambda: _apply_windows_material(
                self.root, bool(self.dark_var.get())))
        except Exception:
            pass

    def _install_resize_guard(self, window):
        """Install resize anti-flicker handling for a top-level window."""
        if getattr(window, "_tb_resize_guard", None):
            return
        window._tb_resize_guard = {"job": None, "suspended": False, "size": None}
        window.bind(
            "<Configure>",
            lambda event, win=window: self._on_window_configure(win, event),
            add="+",
        )
        try:
            def _sync_size(win=window):
                state = getattr(win, "_tb_resize_guard", None)
                if state is not None and win.winfo_exists():
                    state["size"] = (int(win.winfo_width()), int(win.winfo_height()))
            window.after_idle(_sync_size)
        except Exception:
            pass

    def _on_window_configure(self, window, event):
        """Suspend translucent backdrop while resizing; restore after."""
        if event.widget is not window:
            return
        state = getattr(window, "_tb_resize_guard", None)
        if state is None:
            return

        size = (int(event.width), int(event.height))
        last_size = state.get("size")
        state["size"] = size
        if last_size is None or size == last_size:
            return

        hwnd = getattr(window, "_tb_hwnd", None)
        if hwnd and not state.get("suspended"):
            _set_dwm_backdrop(hwnd, bool(self.dark_var.get()), enabled=False)
            state["suspended"] = True

        job = state.get("job")
        if job:
            try:
                window.after_cancel(job)
            except Exception:
                pass
        try:
            state["job"] = window.after(
                180, lambda win=window: self._finish_window_resize(win))
        except Exception:
            state["job"] = None

    def _finish_window_resize(self, window):
        """Restore Acrylic/Mica after continuous resizing has stopped."""
        state = getattr(window, "_tb_resize_guard", None)
        if state is None:
            return
        state["job"] = None
        if not state.get("suspended"):
            return
        try:
            if window.winfo_exists():
                _apply_windows_material(window, bool(self.dark_var.get()))
        finally:
            state["suspended"] = False

    def _toggle_theme(self):
        self._apply_theme()
        self.save_cfg(silent=True)

    def _apply_icon_to(self, window):
        """设置指定窗口的标题栏、任务栏图标。"""
        try:
            if os.path.exists(APP_ICON_ICO):
                window.iconbitmap(APP_ICON_ICO)
        except Exception:
            pass
        try:
            if os.path.exists(APP_ICON_PNG):
                img = tk.PhotoImage(file=APP_ICON_PNG)
                window.iconphoto(True, img)
                self._icon_images.append(img)
        except Exception:
            pass
        try:
            window.update_idletasks()
            _set_native_window_icon(window)
        except Exception:
            pass

    def _set_icon(self):
        """设置主窗口 / 任务栏图标（打包与源码运行均可）。"""
        if not hasattr(self, "_icon_images"):
            self._icon_images = []
        self._apply_icon_to(self.root)
        if not getattr(self, "_icon_late_scheduled", False):
            self._icon_late_scheduled = True
            self.root.after(120, lambda: self._apply_icon_to(self.root))

    def _build_widgets(self):
        # ---------- 配置 ----------
        top = ttk.LabelFrame(self.root, text="配置", padding=(10, 8))
        top.pack(fill="x", padx=12, pady=(12, 6))

        def cfg_label(text):
            return ttk.Label(top, text=text, width=10, anchor="w")

        cfg_label("API Key：").grid(row=0, column=0, sticky="w")
        self.apikey_var = tk.StringVar(value=self.cfg.get("apikey", ""))
        self.apikey_entry = ttk.Entry(top, textvariable=self.apikey_var, width=70, show="*")
        self.apikey_entry.grid(row=0, column=1, sticky="we", padx=(0, 8))
        self.apikey_entry.bind("<Return>", lambda _e: self.save_cfg())
        self.show_key_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="显示", variable=self.show_key_var,
                        command=self._toggle_key).grid(row=0, column=2, sticky="w", padx=(0, 8))
        ttk.Button(top, text="保存配置", command=self.save_cfg, width=10).grid(
            row=0, column=3, sticky="e")

        cfg_label("界面模式：").grid(row=1, column=0, sticky="w", pady=(8, 0))
        mode_row = ttk.Frame(top)
        mode_row.grid(row=1, column=1, columnspan=3, sticky="w", pady=(8, 0))
        self.dark_var = tk.BooleanVar(value=bool(self.cfg.get("dark", False)))
        ttk.Checkbutton(mode_row, text="暗色模式", variable=self.dark_var,
                        command=self._toggle_theme).pack(side="left")

        # 返回语言固定为中文。
        self.lang_var = tk.StringVar(value="zh")

        top.columnconfigure(1, weight=1)

        # ---------- 输入 ----------
        mid = ttk.LabelFrame(self.root, text="批量输入（IP、域名与文件哈希可混合；每行一个或用逗号/空格/分号分隔）", padding=10)
        mid.pack(fill="both", expand=False, padx=12, pady=6)

        self.input_text = ScrolledText(mid, height=6, font=(self.font_family, 10), wrap="word")
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
        self._configure_tree_columns(self.tree, res_cols, res_heads, res_widths, res_align)
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
        self._configure_tree_columns(self.domain_tree, dm_cols, dm_heads, dm_widths, dm_align)
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
        self._configure_tree_columns(self.file_tree, file_cols, file_heads, file_widths, file_align)
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
        ttk.Button(status_bar, text="查看缓存", command=self.show_cache_viewer,
                   style="Small.TButton", width=8).grid(row=0, column=2, sticky="ns", padx=(4, 2), pady=1)
        ttk.Button(status_bar, text="清空缓存", command=self.clear_cache,
                   style="Small.TButton", width=8).grid(row=0, column=3, sticky="ns", padx=(2, 4), pady=1)
        ttk.Label(status_bar, text="作者：Uncledavid", anchor="e",
                  relief="sunken", padding=(8, 3)).grid(row=0, column=4, sticky="ns")
        self._refresh_cache_status()

    # ---------------- 事件 ----------------
    def _toggle_key(self):
        self.apikey_entry.configure(show="" if self.show_key_var.get() else "*")

    def _cache_counts(self):
        """返回当前本地缓存各类型数量。"""
        ip = self.cache.get("ip", {}) if isinstance(self.cache, dict) else {}
        dm = self.cache.get("domain", {}) if isinstance(self.cache, dict) else {}
        fm = self.cache.get("file", {}) if isinstance(self.cache, dict) else {}
        return (
            len(ip) if isinstance(ip, dict) else 0,
            len(dm) if isinstance(dm, dict) else 0,
            len(fm) if isinstance(fm, dict) else 0,
        )

    def _refresh_cache_status(self):
        """刷新底部常驻的本地缓存统计。"""
        if not hasattr(self, "cache_info_var"):
            return
        n_ip, n_dm, n_fm = self._cache_counts()
        hits = getattr(self, "_cached_hits", 0)
        self.cache_info_var.set(f"本地缓存：IP {n_ip} / 域名 {n_dm} / 文件 {n_fm} ｜ 本次命中缓存：{hits}")

    def _close_cache_viewer(self):
        win = getattr(self, "cache_window", None)
        if win is not None and win.winfo_exists():
            win.destroy()
        self.cache_window = None
        self.cache_trees = {}

    def show_cache_viewer(self):
        """打开本地缓存查看窗口，按 IP / 域名 / 文件三个分类列出全部缓存。"""
        win = getattr(self, "cache_window", None)
        if win is not None and win.winfo_exists():
            win.deiconify()
            win.lift()
            win.focus_force()
            self._refresh_cache_window()
            return

        win = tk.Toplevel(self.root)
        # 先隐藏窗口再构建：Toplevel 默认会在屏幕左上角以原始尺寸短暂映射，
        # 若先显示再居中，就会出现「左上角闪出一个小窗」的现象。
        win.withdraw()
        self.cache_window = win
        win.title(f"本地缓存查看 - {APP_NAME} v{VERSION}")
        win.transient(self.root)
        win.protocol("WM_DELETE_WINDOW", self._close_cache_viewer)
        _center_window(win, 1400, 780, min_width=900, min_height=540)
        self._build_cache_viewer(win)
        self._apply_icon_to(win)
        _apply_windows_material(win, bool(self.dark_var.get()))
        self._install_resize_guard(win)
        self._refresh_cache_window()
        # 尺寸、内容、图标与毛玻璃效果全部就绪后再显示，避免可见的跳变。
        try:
            win.deiconify()
            win.lift()
            win.focus_force()
        except Exception:
            pass
        try:
            win.after(120, lambda: self._apply_icon_to(win))
            win.after(140, lambda: _apply_windows_material(win, bool(self.dark_var.get())))
        except Exception:
            pass

    def _build_cache_viewer(self, win):
        header = ttk.Frame(win)
        header.pack(fill="x", padx=12, pady=(12, 6))
        self.cache_view_summary_var = tk.StringVar(value="")
        ttk.Label(header, textvariable=self.cache_view_summary_var, anchor="w").pack(
            side="left", fill="x", expand=True)
        ttk.Label(header, text="双击记录可打开详情链接；Shift+滚轮可左右滚动").pack(
            side="left", padx=(8, 10))
        ttk.Button(header, text="刷新", command=self._refresh_cache_window,
                   style="Small.TButton", width=8).pack(side="right")

        notebook = ttk.Notebook(win)
        notebook.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.cache_trees = {}

        configs = {
            "ip": {
                "title": "IP 缓存",
                "columns": ("resource", "verdict", "carrier", "location", "judgments",
                            "tags", "update_time", "permalink"),
                "heads": ("IP", "判定", "运营商", "地理位置", "威胁判定",
                          "标签分类", "更新时间", "详情链接"),
                "widths": (180, 70, 150, 230, 260, 260, 150, 300),
                "align": {"resource": "w", "verdict": "center", "carrier": "w",
                          "location": "w", "judgments": "w", "tags": "w",
                          "update_time": "center", "permalink": "w"},
            },
            "domain": {
                "title": "域名缓存",
                "columns": ("resource", "verdict", "confidence", "severity", "judgments",
                            "categories", "tags", "permalink"),
                "heads": ("域名", "判定", "可信度", "严重级别", "威胁判定",
                          "域名分类", "标签", "详情链接"),
                "widths": (190, 70, 70, 80, 190, 180, 220, 300),
                "align": {"resource": "w", "verdict": "center", "confidence": "center",
                          "severity": "center", "judgments": "w", "categories": "w",
                          "tags": "w", "permalink": "w"},
            },
            "file": {
                "title": "文件缓存",
                "columns": ("resource", "hash_type", "verdict", "threat_level", "score",
                            "file_name", "file_type", "malware_type", "malware_family",
                            "multi_engines", "whitelist", "permalink"),
                "heads": ("哈希", "类型", "判定", "威胁等级", "评分", "文件名", "文件类型",
                          "恶意类型", "家族", "引擎检出", "白名单", "详情链接"),
                "widths": (260, 70, 70, 80, 60, 180, 90, 130, 150, 90, 70, 300),
                "align": {"resource": "w", "hash_type": "center", "verdict": "center",
                          "threat_level": "center", "score": "center", "file_name": "w",
                          "file_type": "center", "malware_type": "w", "malware_family": "w",
                          "multi_engines": "center", "whitelist": "center", "permalink": "w"},
            },
        }

        for key, cfg in configs.items():
            frame = ttk.Frame(notebook)
            notebook.add(frame, text=cfg["title"])
            self._create_cache_tree(frame, key, cfg)

    def _create_cache_tree(self, parent, key, cfg):
        tree = ttk.Treeview(parent, columns=cfg["columns"], show="headings", selectmode="browse")
        self._configure_tree_columns(
            tree, cfg["columns"], cfg["heads"], cfg["widths"], cfg["align"])
        vsb = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(parent, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)
        tree.tag_configure("mal", foreground=self._theme.get("malice_fg", "#d93025"))
        tree.bind("<Double-1>", lambda event, k=key: self._open_cache_permalink(event, k))
        self._bind_horizontal_wheel(tree)
        self.cache_trees[key] = tree

    def _refresh_cache_window(self):
        """刷新本地缓存查看窗口中的所有记录。"""
        win = getattr(self, "cache_window", None)
        if win is None or not win.winfo_exists():
            return
        n_ip, n_dm, n_fm = self._cache_counts()
        if hasattr(self, "cache_view_summary_var"):
            self.cache_view_summary_var.set(
                f"本地缓存共 {n_ip + n_dm + n_fm} 条：IP {n_ip} / 域名 {n_dm} / 文件 {n_fm}")

        trees = getattr(self, "cache_trees", {})
        for tree in trees.values():
            for iid in tree.get_children():
                tree.delete(iid)

        ip_tree = trees.get("ip")
        if ip_tree is not None:
            ip_cache = self.cache.get("ip", {}) if isinstance(self.cache, dict) else {}
            if isinstance(ip_cache, dict):
                for ip, item in sorted(ip_cache.items(), key=lambda kv: str(kv[0]).lower()):
                    if not isinstance(item, dict):
                        ip_tree.insert("", "end", values=(ip, "缓存数据异常", "-", "-", "-", "-", "-", ""))
                        continue
                    basic = item.get("basic") if isinstance(item.get("basic"), dict) else {}
                    judgments = item.get("judgments") or []
                    jt = "、".join(str(j) for j in judgments) if isinstance(judgments, list) else str(judgments)
                    verdict = verdict_from_item(item)
                    tag = ("mal",) if verdict == "恶意" else ()
                    values = (
                        ip,
                        verdict,
                        (basic.get("carrier") or "-"),
                        fmt_location(basic.get("location")) or "-",
                        jt or "-",
                        fmt_tags_classes(item.get("tags_classes")) or "-",
                        item.get("update_time") or "-",
                        item.get("permalink") or "",
                    )
                    ip_tree.insert("", "end", values=values, tags=tag)

        dm_tree = trees.get("domain")
        if dm_tree is not None:
            dm_cache = self.cache.get("domain", {}) if isinstance(self.cache, dict) else {}
            if isinstance(dm_cache, dict):
                for domain, item in sorted(dm_cache.items(), key=lambda kv: str(kv[0]).lower()):
                    if not isinstance(item, dict):
                        dm_tree.insert("", "end", values=(domain, "缓存数据异常", "-", "-", "-", "-", "-", ""))
                        continue
                    judgments = item.get("judgments") or []
                    jt = "、".join(str(j) for j in judgments) if isinstance(judgments, list) else str(judgments)
                    verdict = verdict_from_item(item)
                    confidence = CONFIDENCE_ZH.get(
                        str(item.get("confidence_level", "")).lower(), item.get("confidence_level") or "-")
                    severity = SEVERITY_ZH.get(
                        str(item.get("severity", "")).lower(), item.get("severity") or "-")
                    tag = ("mal",) if verdict == "恶意" else ()
                    values = (
                        domain,
                        verdict,
                        confidence,
                        severity,
                        jt or "-",
                        fmt_domain_categories(item.get("categories")) or "-",
                        fmt_tags_classes(item.get("tags_classes")) or "-",
                        item.get("permalink") or "",
                    )
                    dm_tree.insert("", "end", values=values, tags=tag)

        fm_tree = trees.get("file")
        if fm_tree is not None:
            fm_cache = self.cache.get("file", {}) if isinstance(self.cache, dict) else {}
            if isinstance(fm_cache, dict):
                for resource, item in sorted(fm_cache.items(), key=lambda kv: str(kv[0]).lower()):
                    if not isinstance(item, dict):
                        fm_tree.insert("", "end", values=(resource, file_hash_type(resource).upper() or "-",
                                                          "缓存数据异常", "-", "-", "-", "-", "-", "-", "-", "-", ""))
                        continue
                    summary = item.get("summary") if isinstance(item.get("summary"), dict) else {}
                    multi = item.get("multiengines") if isinstance(item.get("multiengines"), dict) else {}
                    verdict = verdict_from_file_item(item)
                    level = str(summary.get("threat_level", "")).lower()
                    level_text = FILE_THREAT_LEVEL_ZH.get(level, summary.get("threat_level") or "未知")
                    whitelist = "是" if summary.get("is_whitelist") is True else (
                        "否" if summary.get("is_whitelist") is False else "-")
                    tag = ("mal",) if verdict == "恶意" else ()
                    values = (
                        resource,
                        file_hash_type(resource).upper() or "-",
                        verdict,
                        level_text,
                        summary.get("threat_score", "-"),
                        summary.get("file_name") or "-",
                        summary.get("file_type") or "-",
                        summary.get("malware_type") or "-",
                        summary.get("malware_family") or "-",
                        summary.get("multi_engines") or multi.get("detect_rate") or "-",
                        whitelist,
                        item.get("permalink") or "",
                    )
                    fm_tree.insert("", "end", values=values, tags=tag)

    def _open_cache_permalink(self, _event, cache_type):
        tree = getattr(self, "cache_trees", {}).get(cache_type)
        if tree is None:
            return
        sel = tree.selection()
        if not sel:
            return
        values = tree.item(sel[0], "values")
        url = values[-1] if values else ""
        if url and str(url).startswith("http"):
            webbrowser.open(str(url))

    def _update_count(self, _event=None):
        items = parse_input(self.input_text.get("1.0", "end"))
        n_ip = sum(1 for _, k in items if k == "ip")
        n_dm = sum(1 for _, k in items if k == "domain")
        n_fm = sum(1 for _, k in items if k == "file")
        self.count_label.configure(text=f"待查询：{len(items)} 个（IP {n_ip} / 域名 {n_dm} / 文件 {n_fm}）")

    def save_cfg(self, silent=False):
        cfg = {"apikey": self.apikey_var.get().strip(), "lang": self.lang_var.get(),
               "dark": bool(self.dark_var.get())}
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
                    "dark": bool(self.dark_var.get())}
        save_config(self.cfg)

        self.querying = True
        self.query_btn.configure(state="disabled")
        self._clear_results()
        self.status_var.set(f"正在查询 {len(items)} 个资源 ...")
        threading.Thread(target=self._query_worker, args=(items,), daemon=True).start()

    def _query_worker(self, items):
        lang = self.lang_var.get()
        realtime = False
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
            self.root.after(0, self._refresh_cache_window)
            self.root.after(0, self._on_query_done, None)
        except Exception as e:  # noqa: BLE001
            save_cache(self.cache)
            self.root.after(0, self._refresh_cache_status)
            self.root.after(0, self._refresh_cache_window)
            self.root.after(0, self._on_query_done, str(e))

    def clear_cache(self):
        """清空本地结果缓存，并删除缓存文件。"""
        n_ip, n_dm, n_fm = self._cache_counts()
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
        self._refresh_cache_window()
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
    _enable_high_dpi_awareness()
    root = tk.Tk()
    _setup_tk_fonts(root)
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()





