#!/usr/bin/env python3.12
import argparse
import copy
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
    rule_pattern = re.compile(r"^rule\s+name\s+(\S+)$")
    ip_pattern = re.compile(r"^ip-address\s+(\S+)\s+(\d+)$")
    port_pattern = re.compile(r"^port\s+(\d+)$")
    application_info_pattern = re.compile(r"^Application\s+(\S+)\s+Information:$")
    display_rule_pattern = re.compile(r"^Rule Name\s*:\s*(\S+)$")
    display_ip_pattern = re.compile(r"^(?:IP Address|Destination)\s*:\s*(\S+)$")
    display_port_pattern = re.compile(r"^Port\s*:\s*(.*)$")

    matched_lines = []
    object_names = set()
    group_names = set()
    applications: dict[str, dict[str, Any]] = {}
    invalid_ports: list[dict[str, Any]] = []
    current_application: dict[str, Any] | None = None
    current_rule: dict[str, Any] | None = None

    def ensure_application(name: str) -> dict[str, Any]:
        return applications.setdefault(
            name,
            {"name": name, "ports": [], "ip_addresses": [], "rules": []},
        )

    def ensure_rule(application: dict[str, Any], name: str) -> dict[str, Any]:
        for rule in application["rules"]:
            if rule["name"] == name:
                return rule
        rule = {"name": name, "ports": [], "ip_addresses": []}
        application["rules"].append(rule)
        return rule

    def add_ip(
        application: dict[str, Any],
        rule: dict[str, Any] | None,
        pair: dict[str, Any],
    ) -> None:
        if pair not in application["ip_addresses"]:
            application["ip_addresses"].append(pair)
        if rule is not None and pair not in rule["ip_addresses"]:
            rule["ip_addresses"].append(pair)

    def add_port(
        application: dict[str, Any],
        rule: dict[str, Any] | None,
        port: int,
    ) -> None:
        if port < 1 or port > 65535:
            invalid_ports.append(
                {
                    "application": application["name"],
                    "rule": rule["name"] if rule is not None else None,
                    "port": port,
                }
            )
        if port not in application["ports"]:
            application["ports"].append(port)
        if rule is not None and port not in rule["ports"]:
            rule["ports"].append(port)

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
                current_application = ensure_application(name)
                current_rule = None
            else:
                current_application = None
                current_rule = None
            continue

        application_info_match = application_info_pattern.match(line)
        if application_info_match:
            name = application_info_match.group(1)
            if target_name_pattern.match(name):
                object_names.add(name)
                current_application = ensure_application(name)
                current_rule = None
            else:
                current_application = None
                current_rule = None
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

        rule_match = rule_pattern.match(line)
        if rule_match:
            current_rule = ensure_rule(current_application, rule_match.group(1))
            continue

        display_rule_match = display_rule_pattern.match(line)
        if display_rule_match:
            current_rule = ensure_rule(current_application, display_rule_match.group(1))
            continue

        ip_match = ip_pattern.match(line)
        if ip_match:
            pair = {"ip": ip_match.group(1), "mask": int(ip_match.group(2))}
            add_ip(current_application, current_rule, pair)
            continue

        port_match = port_pattern.match(line)
        if port_match:
            port = int(port_match.group(1))
            add_port(current_application, current_rule, port)
            continue

        display_ip_match = display_ip_pattern.match(line)
        if display_ip_match and display_ip_match.group(1) != "-":
            address = display_ip_match.group(1)
            if "/" in address:
                ip, display_mask = address.rsplit("/", 1)
                pair = {"ip": ip, "mask": int(display_mask)}
                add_ip(current_application, current_rule, pair)
            continue

        display_port_match = display_port_pattern.match(line)
        if display_port_match:
            for value in re.findall(r"\d+", display_port_match.group(1)):
                add_port(current_application, current_rule, int(value))

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
            if not application["ports"]:
                continue
            pairs = application["ip_addresses"]
            rules = application["rules"]
            rule_pairs_match = all(
                rule["ip_addresses"]
                and all(pair == expected_pair for pair in rule["ip_addresses"])
                for rule in rules
                if rule["ports"]
            )
            if (
                not pairs
                or any(pair != expected_pair for pair in pairs)
                or not rule_pairs_match
            ):
                all_target_ips_match = False
                invalid_target_applications.append(application["name"])

    return {
        "names": names,
        "object_names": sorted_object_names,
        "group_names": sorted_group_names,
        "lines": matched_lines,
        "applications": application_list,
        "all_ports": all_ports,
        "all_ports_valid": len(invalid_ports) == 0,
        "invalid_ports": invalid_ports,
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
    applications = copy.deepcopy(parsed.get("applications", []))
    group_names = set(parsed.get("group_names", []))
    expected_names = list(parsed.get("object_names", []))
    operations: list[dict[str, Any]] = []
    if mode == "add":
        new_ports = sorted(set(requested) - set(existing))
        removed_ports: list[int] = []
        for port in new_ports:
            _plan_add_port(
                applications,
                operations,
                expected_names,
                base_app_name,
                port,
                rule_port_limit,
                application_rule_limit,
            )
        active_application_names = {
            application["name"] for application in applications if application["ports"]
        }
        missing_group_names = sorted(
            active_application_names - group_names,
            key=lambda name: _name_order(name, base_app_name),
        )
        for app_name in missing_group_names:
            operations.append({"type": "add_to_group", "app_name": app_name})
            group_names.add(app_name)
        effective = sorted(set(existing) | set(new_ports))
    else:
        new_ports = []
        removed_ports = sorted(set(existing) & set(requested))
        _plan_remove_ports(
            applications,
            operations,
            expected_names,
            group_names,
            set(removed_ports),
        )
        effective = sorted(set(existing) - set(removed_ports))
    active_application_names = {
        application["name"] for application in applications if application["ports"]
    }
    reasons = []
    if mode == "add" and new_ports:
        reasons.append("requested_ports_missing")
    if mode == "add" and active_application_names - set(parsed.get("group_names", [])):
        reasons.append("application_group_members_missing")
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
        "desired_names": sorted(
            active_application_names,
            key=lambda name: _name_order(name, base_app_name),
        ),
        "operations": operations,
        "change_needed": bool(operations),
        "change_reasons": reasons,
    }


def _plan_add_port(
    applications: list[dict[str, Any]],
    operations: list[dict[str, Any]],
    expected_names: list[str],
    base_app_name: str,
    port: int,
    rule_port_limit: int,
    application_rule_limit: int,
) -> None:
    for application in applications:
        for rule in application["rules"]:
            if len(rule["ports"]) < rule_port_limit:
                rule["ports"].append(port)
                application["ports"].append(port)
                operations.append(
                    {
                        "type": "add_ports",
                        "app_name": application["name"],
                        "rule_name": rule["name"],
                        "ports": [port],
                    }
                )
                return

    for application in applications:
        if len(application["rules"]) < application_rule_limit:
            rule_name = _first_available_rule_name(application, application_rule_limit)
            application["rules"].append(
                {"name": rule_name, "ports": [port], "ip_addresses": []}
            )
            application["ports"].append(port)
            operations.append(
                {
                    "type": "add_rule",
                    "app_name": application["name"],
                    "rule_name": rule_name,
                    "ports": [port],
                }
            )
            return

    app_name = _next_application_name(expected_names, base_app_name)
    expected_names.append(app_name)
    applications.append(
        {
            "name": app_name,
            "ports": [port],
            "ip_addresses": [],
            "rules": [{"name": "1", "ports": [port], "ip_addresses": []}],
        }
    )
    operations.extend(
        [
            {"type": "create_application", "app_name": app_name},
            {
                "type": "add_rule",
                "app_name": app_name,
                "rule_name": "1",
                "ports": [port],
            },
        ]
    )


def _plan_remove_ports(
    applications: list[dict[str, Any]],
    operations: list[dict[str, Any]],
    expected_names: list[str],
    group_names: set[str],
    removed_ports: set[int],
) -> None:
    for application in applications:
        app_removed_any = False
        for rule in application["rules"]:
            original_rule_ports = list(rule["ports"])
            ports_to_remove = [port for port in rule["ports"] if port in removed_ports]
            if not ports_to_remove:
                continue
            app_removed_any = True
            rule["ports"] = [port for port in rule["ports"] if port not in removed_ports]
            application["ports"] = [
                port for port in application["ports"] if port not in ports_to_remove
            ]
            if not rule["ports"]:
                operations.append(
                    {
                        "type": "remove_ports",
                        "app_name": application["name"],
                        "rule_name": rule["name"],
                        "ports": ports_to_remove,
                    }
                )
                operations.append(
                    {
                        "type": "remove_rule",
                        "app_name": application["name"],
                        "rule_name": rule["name"],
                    }
                )
            elif _ports_to_remove_are_rule_suffix(original_rule_ports, ports_to_remove):
                operations.append(
                    {
                        "type": "remove_ports",
                        "app_name": application["name"],
                        "rule_name": rule["name"],
                        "ports": ports_to_remove,
                    }
                )
            else:
                operations.append(
                    {
                        "type": "replace_rule_ports",
                        "app_name": application["name"],
                        "rule_name": rule["name"],
                        "old_ports": original_rule_ports,
                        "ports": rule["ports"],
                    }
                )
        if app_removed_any and not application["ports"]:
            if application["name"] in group_names:
                operations.append(
                    {"type": "remove_application", "app_name": application["name"]}
                )
                group_names.remove(application["name"])
            if application["name"] in expected_names:
                expected_names.remove(application["name"])


def _ports_to_remove_are_rule_suffix(
    rule_ports: list[int],
    ports_to_remove: list[int],
) -> bool:
    if not ports_to_remove:
        return True
    return rule_ports[-len(ports_to_remove) :] == ports_to_remove


def _first_available_rule_name(
    application: dict[str, Any],
    application_rule_limit: int,
) -> str:
    used = {str(rule["name"]) for rule in application["rules"]}
    for candidate in range(1, application_rule_limit + 1):
        if str(candidate) not in used:
            return str(candidate)
    raise ValueError("application has no available rule slot")


def _next_application_name(existing_names: list[str], base_app_name: str) -> str:
    existing = set(existing_names)
    if base_app_name not in existing:
        return base_app_name
    suffix = 2
    while True:
        candidate = f"{base_app_name}_{suffix}"
        if candidate not in existing:
            return candidate
        suffix += 1


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
