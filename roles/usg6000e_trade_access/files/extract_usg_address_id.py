#!/usr/bin/env python3.12
import argparse
import json
import re
import sys


def normalize_text(text: str) -> str:
    # 去掉 ANSI 控制字符，避免设备输出里有隐藏字符影响匹配
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)
    text = text.replace("\r", "\n")
    return text


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    parser.add_argument("--ip", required=True)
    parser.add_argument("--mask", default="32")
    args = parser.parse_args()

    try:
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except Exception as e:
        print(json.dumps({"ids": [], "lines": [], "error": str(e)}, ensure_ascii=False))
        return 0

    text = normalize_text(text)

    ids = []
    lines = []

    # 只匹配真正的 address 成员行：
    # address 190 192.168.66.13 mask 32 description xxx
    # 这里不做模糊匹配，避免把描述或别的 IP 输出误当成地址对象。
    pattern = re.compile(
        r"\baddress\s+(\d+)\s+"
        + re.escape(args.ip)
        + r"\s+mask\s+"
        + re.escape(str(args.mask))
        + r"\b"
    )

    for raw_line in text.splitlines():
        line = " ".join(raw_line.strip().split())
        m = pattern.search(line)
        if m:
            ids.append(m.group(1))
            lines.append(line)

    print(json.dumps({"ids": ids, "lines": lines}, ensure_ascii=False))


if __name__ == "__main__":
    main()
