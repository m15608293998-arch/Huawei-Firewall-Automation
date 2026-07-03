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
        + r")\s+mask\s+(?P<mask>\d+)\b"
    )
    for raw_line in normalize_text(text).splitlines():
        line = " ".join(raw_line.strip().split())
        match = pattern.search(line)
        if not match:
            continue
        ip_value = valid_ipv4(match.group("ip"))
        if ip_value is None:
            continue
        addresses[ip_value] = int(match.group("mask"))
    return addresses


def parse_application_config(text: str, prefix: str) -> dict[str, Any]:
    declaration_prefix = "user-defined-application name "
    display_header_pattern = re.compile(r"^Application\s+(\S+)\s+Information:$")
    group_pattern = re.compile(r"^add\s+application\s+(\S+)$")
    config_ip_pattern = re.compile(r"^ip-address\s+(\S+)\s+(\d+)$")
    config_port_pattern = re.compile(r"^port\s+(\d+)$")
    display_ip_pattern = re.compile(r"^IP Address\s*:\s*(\S+)$")
    display_port_pattern = re.compile(r"^Port\s*:\s*(.*)$")

    applications: dict[str, dict[str, Any]] = {}
    object_names: set[str] = set()
    group_names: set[str] = set()
    current_name: str | None = None

    def ensure_application(name: str) -> dict[str, Any]:
        target_ip = application_ip_from_name(name, prefix)
        application = applications.setdefault(
            name,
            {
                "name": name,
                "target_ip": target_ip,
                "ip_addresses": [],
                "ports": [],
            },
        )
        return application

    for raw_line in normalize_text(text).splitlines():
        line = " ".join(raw_line.strip().split())
        if not line:
            continue

        if line.startswith(declaration_prefix):
            name = line[len(declaration_prefix) :].strip().strip('"')
            if application_ip_from_name(name, prefix):
                object_names.add(name)
                ensure_application(name)
                current_name = name
            else:
                current_name = None
            continue

        display_header_match = display_header_pattern.match(line)
        if display_header_match:
            name = display_header_match.group(1)
            if application_ip_from_name(name, prefix):
                object_names.add(name)
                ensure_application(name)
                current_name = name
            else:
                current_name = None
            continue

        group_match = group_pattern.match(line)
        if group_match:
            name = group_match.group(1)
            if application_ip_from_name(name, prefix):
                group_names.add(name)
            continue

        if current_name is None:
            continue

        application = applications[current_name]
        config_ip_match = config_ip_pattern.match(line)
        if config_ip_match:
            ip_value = valid_ipv4(config_ip_match.group(1))
            if ip_value:
                pair = {"ip": ip_value, "mask": int(config_ip_match.group(2))}
                if pair not in application["ip_addresses"]:
                    application["ip_addresses"].append(pair)
            continue

        config_port_match = config_port_pattern.match(line)
        if config_port_match:
            port = int(config_port_match.group(1))
            if port not in application["ports"]:
                application["ports"].append(port)
            continue

        display_ip_match = display_ip_pattern.match(line)
        if display_ip_match and display_ip_match.group(1) != "-":
            address = display_ip_match.group(1)
            if "/" in address:
                ip_value, mask = address.rsplit("/", 1)
                normalized_ip = valid_ipv4(ip_value)
                if normalized_ip:
                    pair = {"ip": normalized_ip, "mask": int(mask)}
                    if pair not in application["ip_addresses"]:
                        application["ip_addresses"].append(pair)
            continue

        display_port_match = display_port_pattern.match(line)
        if display_port_match:
            for value in re.findall(r"\d+", display_port_match.group(1)):
                port = int(value)
                if port not in application["ports"]:
                    application["ports"].append(port)

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
            if application_ip_from_name(name, prefix):
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


def address_presence_for_ip(ip_value: str, address_state: dict[str, Any]) -> dict[str, bool]:
    return {
        vsystem: ip_value in address_state["by_vsystem"].get(vsystem, {})
        for vsystem in address_state["vsystems"]
    }


def mask_for_ip(ip_value: str, address_state: dict[str, Any], fallback: int = 32) -> int:
    for vsystem in address_state["vsystems"]:
        mask = address_state["by_vsystem"].get(vsystem, {}).get(ip_value)
        if mask is not None:
            return int(mask)
    return fallback


def state_for_item(
    address_presence: dict[str, bool],
    application: dict[str, Any] | None,
    in_application_group: bool,
    has_port: bool,
) -> str:
    address_complete = bool(address_presence) and all(address_presence.values())
    has_any_address = any(address_presence.values())
    if application is None:
        return "ip_only" if address_complete else "partial_address"

    target_ip = application["target_ip"]
    expected_pair = {"ip": target_ip, "mask": 32}
    ip_pairs = application["ip_addresses"]
    if ip_pairs and expected_pair not in ip_pairs:
        return "ip_mismatch"
    if not address_complete:
        return "partial_address" if has_any_address else "orphan_application"
    if not in_application_group:
        return "group_missing"
    if not has_port:
        return "application_without_port"
    return "allowed"


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
        presence = address_presence_for_ip(ip_value, address_state)
        items.append(
            {
                "target_ip": ip_value,
                "mask": mask_for_ip(ip_value, address_state),
                "state": "allowed" if all(presence.values()) else "partial_address",
                "address_presence": presence,
            }
        )
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

    applications_by_ip: dict[str, list[dict[str, Any]]] = {}
    for application in application_state["applications"]:
        target_ip = application.get("target_ip")
        if target_ip:
            applications_by_ip.setdefault(target_ip, []).append(application)

    items: list[dict[str, Any]] = []
    all_ips = sorted(
        applications_by_ip,
        key=lambda value: int(ipaddress.IPv4Address(value)),
    )
    for ip_value in all_ips:
        presence = address_presence_for_ip(ip_value, address_state)
        for application in applications_by_ip[ip_value]:
            ports = sorted({int(port) for port in application["ports"]})
            row_ports: list[int | None] = ports or [None]
            in_group = application["name"] in group_names
            fallback_mask = 32
            if application["ip_addresses"]:
                fallback_mask = int(application["ip_addresses"][0]["mask"])
            for port in row_ports:
                items.append(
                    {
                        "target_ip": ip_value,
                        "mask": mask_for_ip(ip_value, address_state, fallback_mask),
                        "port": port,
                        "state": state_for_item(
                            presence,
                            application,
                            in_group,
                            port is not None,
                        ),
                        "address_presence": presence,
                        "application_vsystem": application_vsystem,
                        "application": application["name"],
                        "application_group": application_group,
                        "in_application_group": in_group,
                    }
                )

    items.sort(
        key=lambda item: (
            int(ipaddress.IPv4Address(item["target_ip"])),
            -1 if item["port"] is None else int(item["port"]),
            item["application"] or "",
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
    address_state = build_address_state(address_sources)
    port_items = build_port_items(
        address_state,
        application_inventory_text,
        application_details_text,
        application_group_text,
        application_prefix,
        application_vsystem,
        application_group,
    )
    port_ips = {item["target_ip"] for item in port_items}
    address_ips = {
        ip_value
        for address_map in address_state["by_vsystem"].values()
        for ip_value in address_map
    }
    items: list[dict[str, Any]] = list(port_items)
    all_ips = sorted(
        address_ips - port_ips,
        key=lambda value: int(ipaddress.IPv4Address(value)),
    )
    for ip_value in all_ips:
        presence = address_presence_for_ip(ip_value, address_state)
        items.append(
            {
                "target_ip": ip_value,
                "mask": mask_for_ip(ip_value, address_state),
                "port": None,
                "state": state_for_item(presence, None, False, False),
                "address_presence": presence,
                "application_vsystem": application_vsystem,
                "application": None,
                "application_group": application_group,
                "in_application_group": False,
            }
        )

    items.sort(
        key=lambda item: (
            int(ipaddress.IPv4Address(item["target_ip"])),
            -1 if item["port"] is None else int(item["port"]),
            item["application"] or "",
        )
    )
    return {"generated_at": generated_at_iso(), "items": items}


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
