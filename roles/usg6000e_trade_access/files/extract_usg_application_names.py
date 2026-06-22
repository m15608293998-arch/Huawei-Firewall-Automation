#!/usr/bin/env python3.12
import argparse
import json
import re
from typing import Any


ANSI_PATTERN = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
PAGER_MARKER = "---- More ----"


def normalize_text(text: str) -> str:
    normalized = ANSI_PATTERN.sub("", text).replace("\r", "\n")
    return normalized.replace(PAGER_MARKER, "")


def _application_name_pattern(base_app_name: str) -> re.Pattern[str]:
    return re.compile(r"^" + re.escape(base_app_name) + r"(?:_[0-9]+)?$")


def _name_order(name: str, base_app_name: str) -> tuple[int, str]:
    if name == base_app_name:
        return (1, name)
    suffix = name[len(base_app_name) + 1 :]
    return (int(suffix), name)


def extract_application_names(text: str, base_app_name: str) -> dict[str, list[str]]:
    parsed = extract_application_config(text, base_app_name)
    return {
        "names": parsed["names"],
        "lines": parsed["lines"],
    }


def extract_application_config(
    text: str,
    base_app_name: str,
    target_ip: str | None = None,
    mask: int | None = None,
) -> dict[str, Any]:
    normalized_text = normalize_text(text)
    # 同时兼容配置视图和 display 输出，两种格式里应用名称/端口字段不完全一样。
    target_name_pattern = _application_name_pattern(base_app_name)
    declaration_pattern = re.compile(r"^user-defined-application\s+name\s+(\S+)$")
    group_pattern = re.compile(r"^add\s+application\s+(\S+)$")
    ip_pattern = re.compile(r"^ip-address\s+(\S+)\s+(\d+)$")
    port_pattern = re.compile(r"^port\s+(\d+)$")
    application_info_pattern = re.compile(r"^Application\s+(\S+)\s+Information:$")
    display_ip_pattern = re.compile(r"^IP Address\s*:\s*(\S+)$")
    display_port_pattern = re.compile(r"^Port\s*:\s*(.*)$")

    matched_lines = []
    object_names = set()
    group_names = set()
    applications: dict[str, dict[str, Any]] = {}
    current_application: dict[str, Any] | None = None

    for raw_line in normalized_text.splitlines():
        line = " ".join(raw_line.strip().split())
        if not line:
            continue

        # 解析到非目标应用时清空上下文，避免后续端口/IP 记到上一条目标应用上。
        declaration_match = declaration_pattern.match(line)
        if declaration_match:
            name = declaration_match.group(1)
            if target_name_pattern.match(name):
                object_names.add(name)
                matched_lines.append(line)
                current_application = applications.setdefault(
                    name,
                    {"name": name, "ports": [], "ip_addresses": []},
                )
            else:
                current_application = None
            continue

        application_info_match = application_info_pattern.match(line)
        if application_info_match:
            name = application_info_match.group(1)
            if target_name_pattern.match(name):
                object_names.add(name)
                current_application = applications.setdefault(
                    name,
                    {"name": name, "ports": [], "ip_addresses": []},
                )
            else:
                current_application = None
            continue

        group_match = group_pattern.match(line)
        if group_match:
            name = group_match.group(1)
            if target_name_pattern.match(name):
                group_names.add(name)
                matched_lines.append(line)
            continue

        if current_application is None:
            continue

        ip_match = ip_pattern.match(line)
        if ip_match:
            pair = {"ip": ip_match.group(1), "mask": int(ip_match.group(2))}
            if pair not in current_application["ip_addresses"]:
                current_application["ip_addresses"].append(pair)
            continue

        port_match = port_pattern.match(line)
        if port_match:
            port = int(port_match.group(1))
            if port not in current_application["ports"]:
                current_application["ports"].append(port)
            continue

        display_ip_match = display_ip_pattern.match(line)
        if display_ip_match and display_ip_match.group(1) != "-":
            address = display_ip_match.group(1)
            if "/" in address:
                ip, display_mask = address.rsplit("/", 1)
                pair = {"ip": ip, "mask": int(display_mask)}
                if pair not in current_application["ip_addresses"]:
                    current_application["ip_addresses"].append(pair)
            continue

        display_port_match = display_port_pattern.match(line)
        if display_port_match:
            for value in re.findall(r"\d+", display_port_match.group(1)):
                port = int(value)
                if port not in current_application["ports"]:
                    current_application["ports"].append(port)

    sorted_object_names = sorted(
        object_names,
        key=lambda name: _name_order(name, base_app_name),
    )
    sorted_group_names = sorted(
        group_names,
        key=lambda name: _name_order(name, base_app_name),
    )
    names = sorted(
        object_names | group_names,
        key=lambda name: _name_order(name, base_app_name),
    )
    application_list = [applications[name] for name in sorted_object_names]
    all_ports = sorted(
        {port for application in application_list for port in application["ports"]}
    )

    all_target_ips_match = True
    invalid_target_applications = []
    if target_ip is not None and mask is not None:
        # 删除端口前确认应用对象仍指向目标 IP，避免改到同名但不同地址的对象。
        expected_pair = {"ip": target_ip, "mask": int(mask)}
        for application in application_list:
            pairs = application["ip_addresses"]
            if not pairs or any(pair != expected_pair for pair in pairs):
                all_target_ips_match = False
                invalid_target_applications.append(application["name"])

    return {
        "names": names,
        "object_names": sorted_object_names,
        "group_names": sorted_group_names,
        "lines": matched_lines,
        "applications": application_list,
        "all_ports": all_ports,
        "all_target_ips_match": all_target_ips_match,
        "invalid_target_applications": invalid_target_applications,
    }


def build_application_plan(
    parsed: dict[str, Any],
    base_app_name: str,
    requested_ports: list[int],
    rule_port_limit: int = 4,
    application_rule_limit: int = 8,
    mode: str = "add",
) -> dict[str, Any]:
    if mode not in {"add", "remove"}:
        raise ValueError("mode must be add or remove")
    requested = sorted({int(port) for port in requested_ports})
    existing = sorted({int(port) for port in parsed["all_ports"]})
    if mode == "add":
        effective = sorted(set(existing) | set(requested))
        new_ports = sorted(set(requested) - set(existing))
        removed_ports: list[int] = []
    else:
        effective = sorted(set(existing) - set(requested))
        new_ports = []
        removed_ports = sorted(set(existing) & set(requested))
    application_capacity = rule_port_limit * application_rule_limit

    units = []
    # Huawei 一个应用对象能容纳的端口有限，超出后按 base、base_2... 分片。
    for offset in range(0, len(effective), application_capacity):
        index = offset // application_capacity + 1
        ports = effective[offset : offset + application_capacity]
        app_name = base_app_name if index == 1 else f"{base_app_name}_{index}"
        units.append(
            {
                "index": index,
                "app_name": app_name,
                "ports": ports,
                "rule_port_groups": [
                    ports[start : start + rule_port_limit]
                    for start in range(0, len(ports), rule_port_limit)
                ],
            }
        )

    desired_names = [unit["app_name"] for unit in units]
    reasons = []
    if sorted(parsed["object_names"]) != sorted(desired_names):
        reasons.append("application_objects_do_not_match_plan")
    if sorted(parsed["group_names"]) != sorted(desired_names):
        reasons.append("application_group_members_do_not_match_plan")
    if mode == "add" and new_ports:
        reasons.append("requested_ports_missing")
    if mode == "remove" and removed_ports:
        reasons.append("requested_ports_present")
    if not parsed["all_target_ips_match"]:
        reasons.append("application_target_ip_mismatch")

    return {
        "mode": mode,
        "requested_ports": requested,
        "existing_ports": existing,
        "effective_ports": effective,
        "new_ports": new_ports,
        "removed_ports": removed_ports,
        "desired_names": desired_names,
        "units": units,
        "rebuild_needed": bool(reasons),
        "rebuild_reasons": reasons,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    parser.add_argument("--base-app-name", required=True)
    parser.add_argument("--target-ip")
    parser.add_argument("--mask", type=int)
    parser.add_argument("--requested-ports-json")
    parser.add_argument("--mode", choices=["add", "remove"], default="add")
    parser.add_argument("--rule-port-limit", type=int, default=4)
    parser.add_argument("--application-rule-limit", type=int, default=8)
    args = parser.parse_args()

    try:
        with open(args.file, "r", encoding="utf-8", errors="ignore") as handle:
            text = handle.read()
    except OSError as exc:
        print(json.dumps({"names": [], "lines": [], "error": str(exc)}))
        return 1

    parsed = extract_application_config(
        text,
        args.base_app_name,
        target_ip=args.target_ip,
        mask=args.mask,
    )
    if args.requested_ports_json is not None:
        try:
            requested_ports = json.loads(args.requested_ports_json)
        except json.JSONDecodeError as exc:
            print(json.dumps({"error": f"invalid requested ports JSON: {exc}"}))
            return 2
        parsed["plan"] = build_application_plan(
            parsed,
            args.base_app_name,
            requested_ports,
            rule_port_limit=args.rule_port_limit,
            application_rule_limit=args.application_rule_limit,
            mode=args.mode,
        )

    print(json.dumps(parsed, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
