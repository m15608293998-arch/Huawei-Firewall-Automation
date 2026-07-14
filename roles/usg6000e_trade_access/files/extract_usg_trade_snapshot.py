#!/usr/bin/env python3.12
import argparse
import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ANSI_PATTERN = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
PAGER_MARKER = "---- More ----"
IPV4_PATTERN = r"(?:\d{1,3}\.){3}\d{1,3}"


def normalize_text(text: str) -> str:
    normalized = ANSI_PATTERN.sub("", text).replace("\r", "\n")
    return normalized.replace(PAGER_MARKER, "")


def read_text(path: str | None) -> str:
    if not path:
        return ""
    return Path(path).read_text(encoding="utf-8", errors="ignore")


def extract_cli_file_section(text: str, cli_file: str | None) -> str:
    if not cli_file:
        return text
    marker_pattern = re.compile(r"^===== CLI FILE: (.+?) =====$", re.MULTILINE)
    matches = list(marker_pattern.finditer(text))
    if not matches:
        return text
    for index, match in enumerate(matches):
        if match.group(1).strip() != cli_file:
            continue
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        return text[start:end]
    return ""


def valid_ipv4(value: str) -> str | None:
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        return None


def mask_to_prefix(value: str) -> int | None:
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return ipaddress.IPv4Network("0.0.0.0/{0}".format(value)).prefixlen
    except ValueError:
        return None


def parse_address_value(value: str) -> dict[str, int] | None:
    if value == "-":
        return None
    if "/" not in value:
        ip_value = valid_ipv4(value)
        if ip_value is None:
            return None
        return {"ip": ip_value, "mask": 32}
    ip_value, mask_value = value.rsplit("/", 1)
    normalized_ip = valid_ipv4(ip_value)
    mask = mask_to_prefix(mask_value)
    if normalized_ip is None or mask is None:
        return None
    return {"ip": normalized_ip, "mask": mask}


def is_application_name(name: str) -> bool:
    return bool(name) and not any(character.isspace() for character in name)


def application_ip_from_name(name: str, prefix: str) -> str | None:
    if not name.startswith(prefix):
        return None
    suffix = name[len(prefix) :]
    if "_" in suffix:
        candidate, index = suffix.rsplit("_", 1)
        if index.isdigit():
            suffix = candidate
    return valid_ipv4(suffix)


def application_name_sort_key(name: str, prefix: str) -> tuple[int, int, str]:
    ip_value = application_ip_from_name(name, prefix)
    ip_order = int(ipaddress.IPv4Address(ip_value)) if ip_value else 2**32
    suffix = name[len(prefix) :]
    index = 1
    if "_" in suffix:
        _, maybe_index = suffix.rsplit("_", 1)
        if maybe_index.isdigit():
            index = int(maybe_index)
    return (ip_order, index, name)


def parse_address_inventory(text: str) -> dict[str, int]:
    addresses: dict[str, int] = {}
    pattern = re.compile(
        r"\baddress\s+\d+\s+(?P<ip>"
        + IPV4_PATTERN
        + r")\s+mask\s+(?P<mask>\S+)\b"
    )
    for raw_line in normalize_text(text).splitlines():
        line = " ".join(raw_line.strip().split())
        match = pattern.search(line)
        if not match:
            continue
        ip_value = valid_ipv4(match.group("ip"))
        mask = mask_to_prefix(match.group("mask"))
        if ip_value is None or mask is None:
            continue
        addresses[ip_value] = mask
    return addresses


def parse_application_config(text: str, prefix: str) -> dict[str, Any]:
    declaration_prefix = "user-defined-application name "
    display_header_pattern = re.compile(r"^Application\s+(\S+)\s+Information:$")
    config_rule_pattern = re.compile(r"^rule\s+name\s+(\S+)$")
    display_rule_pattern = re.compile(r"^Rule Name\s*:\s*(\S+)$")
    group_pattern = re.compile(r"^add\s+application\s+(\S+)$")
    config_ip_pattern = re.compile(r"^ip-address\s+(\S+)\s+(\d+)$")
    config_port_pattern = re.compile(r"^port\s+(\d+)$")
    display_ip_pattern = re.compile(r"^(?:IP Address|Destination)\s*:\s*(\S+)$")
    display_port_pattern = re.compile(r"^Port\s*:\s*(.*)$")

    applications: dict[str, dict[str, Any]] = {}
    object_names: set[str] = set()
    group_names: set[str] = set()
    current_name: str | None = None
    current_rule: dict[str, Any] | None = None

    def ensure_application(name: str) -> dict[str, Any]:
        target_ip = application_ip_from_name(name, prefix)
        application = applications.setdefault(
            name,
            {
                "name": name,
                "target_ip": target_ip,
                "ip_addresses": [],
                "ports": [],
                "rules": [],
            },
        )
        return application

    def ensure_rule(application: dict[str, Any], name: str) -> dict[str, Any]:
        for rule in application["rules"]:
            if rule["name"] == name:
                return rule
        rule = {"name": name, "ip_addresses": [], "ports": []}
        application["rules"].append(rule)
        return rule

    def add_ip_address(application: dict[str, Any], pair: dict[str, int]) -> None:
        if pair not in application["ip_addresses"]:
            application["ip_addresses"].append(pair)
        rule = current_rule or ensure_rule(application, "default")
        if pair not in rule["ip_addresses"]:
            rule["ip_addresses"].append(pair)

    def add_port(application: dict[str, Any], port: int) -> None:
        if port not in application["ports"]:
            application["ports"].append(port)
        rule = current_rule or ensure_rule(application, "default")
        if port not in rule["ports"]:
            rule["ports"].append(port)

    for raw_line in normalize_text(text).splitlines():
        line = " ".join(raw_line.strip().split())
        if not line:
            continue

        if line == "#":
            current_name = None
            current_rule = None
            continue

        if line.startswith(declaration_prefix):
            name = line[len(declaration_prefix) :].strip().strip('"')
            if is_application_name(name):
                object_names.add(name)
                ensure_application(name)
                current_name = name
                current_rule = None
            else:
                current_name = None
                current_rule = None
            continue

        display_header_match = display_header_pattern.match(line)
        if display_header_match:
            name = display_header_match.group(1)
            if is_application_name(name):
                object_names.add(name)
                ensure_application(name)
                current_name = name
                current_rule = None
            else:
                current_name = None
                current_rule = None
            continue

        if line.startswith("application-group name "):
            current_name = None
            current_rule = None
            continue

        group_match = group_pattern.match(line)
        if group_match:
            name = group_match.group(1)
            if is_application_name(name):
                group_names.add(name)
            continue

        if current_name is None:
            continue

        application = applications[current_name]
        rule_match = config_rule_pattern.match(line) or display_rule_pattern.match(line)
        if rule_match:
            current_rule = ensure_rule(application, rule_match.group(1))
            continue

        config_ip_match = config_ip_pattern.match(line)
        if config_ip_match:
            ip_value = valid_ipv4(config_ip_match.group(1))
            mask = mask_to_prefix(config_ip_match.group(2))
            if ip_value and mask is not None:
                add_ip_address(application, {"ip": ip_value, "mask": mask})
            continue

        config_port_match = config_port_pattern.match(line)
        if config_port_match:
            add_port(application, int(config_port_match.group(1)))
            continue

        display_ip_match = display_ip_pattern.match(line)
        if display_ip_match:
            pair = parse_address_value(display_ip_match.group(1))
            if pair:
                add_ip_address(application, pair)
            continue

        continued_address = parse_address_value(line)
        if continued_address:
            add_ip_address(application, continued_address)
            continue

        display_port_match = display_port_pattern.match(line)
        if display_port_match:
            for value in re.findall(r"\d+", display_port_match.group(1)):
                add_port(application, int(value))

    return {
        "object_names": sorted(object_names, key=lambda item: application_name_sort_key(item, prefix)),
        "group_names": sorted(group_names, key=lambda item: application_name_sort_key(item, prefix)),
        "applications": [
            applications[name]
            for name in sorted(applications, key=lambda item: application_name_sort_key(item, prefix))
        ],
    }


def parse_application_group_members(text: str, prefix: str, application_group: str) -> list[str]:
    group_declaration_pattern = re.compile(r"^application-group\s+name\s+(\S+)$")
    member_pattern = re.compile(r"^add\s+application\s+(\S+)$")
    group_names: set[str] = set()
    seen_group_context = False
    in_target_group = False

    for raw_line in normalize_text(text).splitlines():
        line = " ".join(raw_line.strip().split())
        if not line:
            continue

        group_match = group_declaration_pattern.match(line)
        if group_match:
            seen_group_context = True
            in_target_group = group_match.group(1) == application_group
            continue

        if not in_target_group:
            continue

        member_match = member_pattern.match(line)
        if member_match:
            name = member_match.group(1)
            if is_application_name(name):
                group_names.add(name)

    if not seen_group_context:
        return parse_application_config(text, prefix)["group_names"]
    return sorted(group_names, key=lambda item: application_name_sort_key(item, prefix))


def build_address_state(address_sources: list[dict[str, str]]) -> dict[str, Any]:
    vsystems = [source["vsystem"] for source in address_sources]
    by_vsystem: dict[str, dict[str, int]] = {}
    for source in address_sources:
        source_text = read_text(source["path"])
        source_text = extract_cli_file_section(source_text, source.get("cli_file"))
        by_vsystem[source["vsystem"]] = parse_address_inventory(source_text)
    return {"vsystems": vsystems, "by_vsystem": by_vsystem}


def is_allowed_ip(ip_value: str, address_state: dict[str, Any]) -> bool:
    if not address_state["vsystems"]:
        return False
    return all(
        address_state["by_vsystem"].get(vsystem, {}).get(ip_value) == 32
        for vsystem in address_state["vsystems"]
    )


def generated_at_iso() -> str:
    return datetime.now(timezone(timedelta(hours=8))).isoformat(timespec="seconds")


def build_ip_items(address_state: dict[str, Any]) -> list[dict[str, Any]]:
    address_ips = {
        ip_value
        for address_map in address_state["by_vsystem"].values()
        for ip_value in address_map
    }
    items = []
    for ip_value in sorted(address_ips, key=lambda value: int(ipaddress.IPv4Address(value))):
        if is_allowed_ip(ip_value, address_state):
            items.append({"ip": ip_value})
    return items


def build_ip_snapshot(address_sources: list[dict[str, str]]) -> dict[str, Any]:
    address_state = build_address_state(address_sources)
    return {
        "generated_at": generated_at_iso(),
        "items": build_ip_items(address_state),
    }


def build_port_items(
    address_state: dict[str, Any],
    application_inventory_text: str,
    application_details_text: str,
    application_group_text: str,
    application_prefix: str,
    application_vsystem: str,
    application_group: str,
) -> list[dict[str, Any]]:
    application_state = parse_application_config(
        application_inventory_text + "\n" + application_details_text,
        application_prefix,
    )
    group_names = set(
        parse_application_group_members(
            application_group_text,
            application_prefix,
            application_group,
        )
    )

    allowed_ips = {item["ip"] for item in build_ip_items(address_state)}
    emitted: set[tuple[str, int]] = set()
    items: list[dict[str, Any]] = []
    for application in application_state["applications"]:
        if application["name"] not in group_names:
            continue
        for rule in application["rules"]:
            rule_ips = [
                pair["ip"]
                for pair in rule["ip_addresses"]
                if pair["mask"] == 32 and pair["ip"] in allowed_ips
            ]
            if not rule_ips:
                continue
            for target_ip in sorted(
                set(rule_ips),
                key=lambda value: int(ipaddress.IPv4Address(value)),
            ):
                for port in sorted({int(port) for port in rule["ports"]}):
                    key = (target_ip, port)
                    if key in emitted:
                        continue
                    emitted.add(key)
                    items.append({"ip": target_ip, "port": port})

    items.sort(
        key=lambda item: (
            int(ipaddress.IPv4Address(item["ip"])),
            int(item["port"]),
        )
    )
    return items


def build_port_snapshot(
    address_sources: list[dict[str, str]],
    application_inventory_text: str,
    application_details_text: str,
    application_group_text: str,
    application_prefix: str,
    application_vsystem: str,
    application_group: str,
) -> dict[str, Any]:
    address_state = build_address_state(address_sources)
    return {
        "generated_at": generated_at_iso(),
        "items": build_port_items(
            address_state,
            application_inventory_text,
            application_details_text,
            application_group_text,
            application_prefix,
            application_vsystem,
            application_group,
        ),
    }

def build_snapshot(
    address_sources: list[dict[str, str]],
    application_inventory_text: str,
    application_details_text: str,
    application_group_text: str,
    application_prefix: str,
    application_vsystem: str,
    application_group: str,
) -> dict[str, Any]:
    return build_port_snapshot(
        address_sources,
        application_inventory_text,
        application_details_text,
        application_group_text,
        application_prefix,
        application_vsystem,
        application_group,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=["discover", "snapshot", "ips", "ports"],
        default="snapshot",
    )
    parser.add_argument("--address-sources-json")
    parser.add_argument("--application-inventory-file")
    parser.add_argument("--application-details-file")
    parser.add_argument("--application-group-file")
    parser.add_argument("--application-prefix", required=True)
    parser.add_argument("--application-vsystem", default="private")
    parser.add_argument("--application-group", default="UD_TradeGroup_Internet")
    parser.add_argument("--output")
    args = parser.parse_args()

    if args.mode == "discover":
        parsed = parse_application_config(
            read_text(args.application_inventory_file),
            args.application_prefix,
        )
        payload = {"object_names": parsed["object_names"]}
    elif args.mode == "ips":
        if not args.address_sources_json:
            raise SystemExit("--address-sources-json is required in ips mode")
        payload = build_ip_snapshot(json.loads(args.address_sources_json))
    else:
        if not args.address_sources_json:
            raise SystemExit("--address-sources-json is required in snapshot or ports mode")
        builder = build_port_snapshot if args.mode == "ports" else build_snapshot
        payload = builder(
            json.loads(args.address_sources_json),
            read_text(args.application_inventory_file),
            read_text(args.application_details_file),
            read_text(args.application_group_file),
            args.application_prefix,
            args.application_vsystem,
            args.application_group,
        )

    serialized = json.dumps(payload, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(serialized + "\n", encoding="utf-8")
    print(serialized)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
