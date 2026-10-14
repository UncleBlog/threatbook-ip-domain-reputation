#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""打包脚本：从 app.py 读取 VERSION，生成带版本号的可执行文件到 outputs/。

用法（在 build 目录或项目根目录）：
    python build/build_exe.py
生成：
    outputs/微步IP域名信誉查询API调用_v<版本号>.exe
"""
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
APP = os.path.join(HERE, "app.py")
SPEC = os.path.join(HERE, "ThreatBookIPReputation.spec")
DIST_EXE = os.path.join(HERE, "dist", "ThreatBookIPReputation.exe")
OUT_DIR = os.path.join(ROOT, "outputs")
BASE_NAME = "微步IP域名信誉查询API调用"  # Windows 文件名不能含 "/"


def read_version():
    with open(APP, encoding="utf-8") as f:
        m = re.search(r'VERSION\s*=\s*"([^"]+)"', f.read())
    return m.group(1) if m else "0.0.0"


def main():
    version = read_version()
    print(f"==> 开始打包 v{version}")
    subprocess.check_call(
        [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", SPEC],
        cwd=HERE,
    )
    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, f"{BASE_NAME}_v{version}.exe")
    shutil.copy2(DIST_EXE, out)
    print(f"==> 完成，输出：{out}")


if __name__ == "__main__":
    main()
