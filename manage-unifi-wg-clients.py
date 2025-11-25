#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# -----------------------------------------------------------------------------
# manage-unifi-wg-clients.py, Copyright Bjoern Olausson
# -----------------------------------------------------------------------------
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# To view the license visit
# https://www.gnu.org/licenses/gpl-3.0.html
# or write to
# Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
# 02110-1301 USA
# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
#
# This Python 3 program is intended to manage WireGuard users via the Unifi API
#

import sys
import json
import argparse
import base64
import ipaddress
import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning
import configparser
from pathlib import Path
from typing import Optional, Tuple, Any, Dict, List
import time
import os

# 1) readline for better input() editing (backspace, history, etc.)
try:
    import readline  # noqa: F401
except Exception:
    pass

# Suppress only the specific TLS warning when verify=False
urllib3.disable_warnings(InsecureRequestWarning)

# Pretty output
try:
    from prettytable import PrettyTable
except ImportError:
    print("Missing dependency: prettytable. Install with: pip install prettytable", file=sys.stderr)
    sys.exit(1)

# WireGuard key generation (Curve25519) via PyNaCl
try:
    from nacl.public import PrivateKey
except ImportError:
    print("Missing dependency: PyNaCl. Install with: pip install pynacl", file=sys.stderr)
    sys.exit(1)

CONFIG_PATH = Path.home() / ".unifi.conf"
SECTION = "unifi"

VERBOSE = False   # set by -v/--verbose
COLORIZE = True   # set false by -nc/--no-color
QUIET = False     # set by -q/--quiet
ORIGINAL_STDOUT = sys.stdout  # will be set again in main()

# ANSI colors (light blue for requests, light green for responses)
C_REQ = "\033[96m"
C_RESP = "\033[92m"
C_RESET = "\033[0m"

def colorize(s: str, color: str) -> str:
    if COLORIZE:
        return f"{color}{s}{C_RESET}"
    return s

def vprint(*args, **kwargs):
    if VERBOSE:
        print(*args, **kwargs)

def qprint(*args, **kwargs):
    """Print only when not in quiet mode."""
    if not QUIET:
        print(*args, **kwargs)

def sanitize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    redacted = {}
    for k, v in (headers or {}).items():
        kk = k.lower()
        if kk in ("cookie", "authorization", "x-csrf-token"):
            redacted[k] = "***"
        else:
            redacted[k] = v
    return redacted

def vrequest(session: requests.Session, method: str, url: str, **kwargs) -> requests.Response:
    # Prepare printable body/params without secrets
    printable = {k: v for k, v in kwargs.items()}
    if "headers" in printable:
        printable["headers"] = sanitize_headers(printable["headers"])
    if "json" in printable:
        try:
            snippet = json.dumps(printable["json"])
        except Exception:
            snippet = str(printable["json"])
        if len(snippet) > 1200:
            snippet = snippet[:1200] + "...(truncated)"
        printable["json"] = snippet
    if "data" in printable and isinstance(printable["data"], (bytes, str)):
        data = printable["data"]
        snippet = data if isinstance(data, str) else data.decode("utf-8", errors="ignore")
        if len(snippet) > 1200:
            snippet = snippet[:1200] + "...(truncated)"
        printable["data"] = snippet

    # Verbose: request (light blue)
    req_line = f">>> {method.upper()} {url}"
    vprint(colorize(req_line, C_REQ))
    if printable:
        vprint(colorize(f"    kwargs: {printable}", C_REQ))

    resp = session.request(method=method, url=url, **kwargs)

    # Verbose: response (light green)
    ctype = resp.headers.get("Content-Type", "")
    body_preview = ""
    try:
        if "application/json" in (ctype or ""):
            body_preview = json.dumps(resp.json(), indent=2)
        else:
            body_preview = resp.text
        if len(body_preview) > 1200:
            body_preview = body_preview[:1200] + "...(truncated)"
    except Exception:
        body_preview = f"<non-text body, {len(resp.content)} bytes>"

    status_line = f"<<< {resp.status_code} {ctype}"
    vprint(colorize(status_line, C_RESP))
    if body_preview:
        for line in body_preview.splitlines():
            vprint(colorize(f"    {line}", C_RESP))

    return resp

def is_ip_addr(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False

def normalize_allowed_ip(token: str) -> Optional[str]:
    """
    Normalize a token into a valid AllowedIPs entry:
    - If it contains '/', parse as network (strict=False).
    - Else if it's an IP, return /32 (IPv4) or /128 (IPv6).
    """
    token = token.strip()
    if not token:
        return None
    try:
        if "/" in token:
            net = ipaddress.ip_network(token, strict=False)
            return str(net)
        else:
            ip = ipaddress.ip_address(token)
            return f"{ip}/32" if isinstance(ip, ipaddress.IPv4Address) else f"{ip}/128"
    except Exception:
        return None

def parse_additional_allowed_ips(raw: str) -> List[str]:
    out, seen = [], set()
    for token in [t.strip() for t in (raw or "").split(",")]:
        if not token:
            continue
        norm = normalize_allowed_ip(token)
        if norm and norm not in seen:
            seen.add(norm)
            out.append(norm)
    return out

def load_config(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(
            f"Config file not found: {path}\n"
            "Create it with contents like:\n\n"
            "[unifi]\n"
            "gateway = unifi.local\n"
            "username = admin\n"
            "password = \n"
            "site_id = default\n"
            "verify_tls = false\n"
            "default_dns = 1.1.1.1\n"
            "AdditionalAllowedIPs = \n"
            "DefaultWGconfFolder = \n"
            "DefaultWGnetworkName = \n"
        )
    cfg = configparser.ConfigParser()
    with path.open("r", encoding="utf-8") as f:
        cfg.read_file(f)

    if SECTION not in cfg:
        raise KeyError(f"Missing section [{SECTION}] in {path}")

    c = cfg[SECTION]
    gateway = c.get("gateway")
    username = c.get("username")
    password = c.get("password")  # may be empty; we will prompt later if it is
    if not gateway or not username:
        raise ValueError("gateway and username must be set in the config file")

    site_id = c.get("site_id", "default")
    verify_tls = c.getboolean("verify_tls", fallback=True)

    # Optional default DNS (single or comma-separated)
    default_dns_raw = c.get("default_dns", "").strip()
    default_dns_ips = []
    if default_dns_raw:
        for token in [x.strip() for x in default_dns_raw.split(",") if x.strip()]:
            if is_ip_addr(token):
                default_dns_ips.append(token)

    # AdditionalAllowedIPs (comma-separated)
    add_allowed_raw = c.get("AdditionalAllowedIPs", "")
    additional_allowed_ips = parse_additional_allowed_ips(add_allowed_raw)

    # DefaultWGconfFolder (optional)
    default_wg_folder_raw = c.get("DefaultWGconfFolder", "").strip()
    default_wg_folder = Path(default_wg_folder_raw).expanduser() if default_wg_folder_raw else None

    # DefaultWGnetworkName (optional)
    default_wg_network_name = c.get("DefaultWGnetworkName", "").strip() or None

    return {
        "gateway": gateway.strip(),
        "username": username,
        "password": password or "",  # allow empty; will prompt
        "site_id": site_id.strip(),
        "verify_tls": verify_tls,
        "default_dns_ips": default_dns_ips,                 # may be empty
        "additional_allowed_ips": additional_allowed_ips,   # list, may be empty
        "default_wg_conf_folder": default_wg_folder,       # Path or None
        "default_wg_network_name": default_wg_network_name, # str or None
    }

def build_urls(gateway: str, site_id: str) -> Dict[str, str]:
    base = f"https://{gateway}"
    return {
        "BASE": base,
        "SITE": site_id,
        "LOGIN_URL": f"{base}/api/auth/login",
        # Networks listing (legacy REST path aligns with your working flow)
        "NETWORKCONF_URL": f"{base}/proxy/network/api/s/{site_id}/rest/networkconf",
        # v2 WireGuard users listing and ops
        "WG_USERS_V2_BASE": f"{base}/proxy/network/v2/api/site/{site_id}/wireguard",
        # Health info containing WAN IP
        "HEALTH_URL": f"{base}/proxy/network/api/s/{site_id}/stat/health",
    }

def login(session: requests.Session, urls: Dict[str, str], username: str, password: str):
    """
    POST /api/auth/login with retry on 429 (Too Many Requests).
    On 429, print server message and sleep 60s before retrying.
    Retries up to 3 times, then raises. CTRL-C interrupts cleanly (handled in main()).
    """
    payload = {"username": username, "password": password}
    retries = 0
    max_retries = 3
    wait_seconds = 60

    while True:
        try:
            r = vrequest(session, "POST", urls["LOGIN_URL"], json=payload)
            r.raise_for_status()

            csrf = r.headers.get("x-csrf-token") or r.headers.get("X-Csrf-Token")
            if not csrf:
                raise RuntimeError("Login ok but x-csrf-token header not found.")
            session.headers["x-csrf-token"] = csrf

            if not session.cookies.get("TOKEN"):
                raise RuntimeError("Login ok but TOKEN cookie not present.")

            return  # success

        except requests.HTTPError as e:
            status = getattr(e.response, "status_code", None)
            if status == 429:
                # Extract server message
                msg = None
                try:
                    j = e.response.json()
                    msg = j.get("message") or j.get("detail") or j.get("error") or e.response.text
                except Exception:
                    msg = getattr(e.response, "text", str(e))
                if retries >= max_retries:
                    raise requests.HTTPError(
                        f"Login throttled (HTTP 429) after {max_retries} retries: {msg}"
                    ) from e
                retries += 1
                # Informational; goes to stdout and will be suppressed by -q (by design)
                print(f"Login throttled (HTTP 429): {msg}\nRetrying in {wait_seconds} seconds... (retry {retries}/{max_retries})")
                try:
                    time.sleep(wait_seconds)
                except KeyboardInterrupt:
                    raise
                continue
            # Any non-429: re-raise for global handler
            raise

def get_wan_ip(session: requests.Session, urls: Dict[str, str]) -> str:
    r = vrequest(session, "GET", urls["HEALTH_URL"])
    r.raise_for_status()
    data = r.json()
    wanip = data.get("data", [])[1]["wan_ip"]
    return wanip

def list_wireguard_networks(session: requests.Session, urls: Dict[str, str]) -> List[Dict[str, Any]]:
    r = vrequest(session, "GET", urls["NETWORKCONF_URL"])
    r.raise_for_status()
    data = r.json()
    rows = data.get("data", [])
    return [n for n in rows if n.get("vpn_type") == "wireguard-server"]

def print_users_table(users: List[Dict[str, Any]]):
    table = PrettyTable()
    table.field_names = ["#", "Name", "ID", "IP Address"]
    table.align["Name"] = "l"
    table.align["ID"] = "l"
    table.align["IP Address"] = "l"
    for i, u in enumerate(users, 1):
        name = u.get("name") or ""
        uid = u.get("_id") or ""
        ip = u.get("interface_ip") or ""
        table.add_row([i, name, uid, ip])
    print("\nWireGuard users")
    print(table)

def select_network(wg_networks: List[Dict[str, Any]]) -> Dict[str, Any]:
    table = PrettyTable()
    table.field_names = ["#", "Name", "ID", "Subnet", "Endpoint", "Port"]
    table.align["Name"] = "l"
    table.align["ID"] = "l"
    table.align["Subnet"] = "l"
    table.align["Endpoint"] = "l"
    for i, n in enumerate(wg_networks, 1):
        name = n.get("name") or n.get("display_name") or n.get("_id")
        nid = n.get("_id") or ""
        subnet = n.get("ip_subnet") or ""
        host = n.get("vpn_client_configuration_remote_ip_override") or n.get("wireguard_local_wan_ip") or ""
        port = n.get("local_port") or ""
        table.add_row([i, name, nid, subnet, host, port])

    print("\nAvailable WireGuard VPN networks")
    print(table)

    while True:
        choice = input("Select network by number: ").strip()
        if not choice.isdigit():
            print("Please enter a number.")
            continue
        idx = int(choice)
        if 1 <= idx <= len(wg_networks):
            return wg_networks[idx - 1]
        print("Invalid selection.")

def resolve_network_selector(wg_networks: List[Dict[str, Any]], selector: str) -> Dict[str, Any]:
    # Try exact _id
    for n in wg_networks:
        if n.get("_id") == selector:
            return n
    # Try case-insensitive exact name
    for n in wg_networks:
        if (n.get("name") or "").lower() == selector.lower():
            return n
    # Not found
    raise ValueError(f"Network '{selector}' not found by id or name.")

def list_wireguard_users_v2(session: requests.Session, urls: Dict[str, str], network_id: str) -> List[Dict[str, Any]]:
    url = f"{urls['WG_USERS_V2_BASE']}/{network_id}/users"
    r = vrequest(session, "GET", url, params={"networkId": network_id})
    r.raise_for_status()
    data = r.json()
    return data if isinstance(data, list) else data.get("data", [])

def find_user_by_name(users: List[Dict[str, Any]], name: str) -> Optional[Dict[str, Any]]:
    target = (name or "").strip().lower()
    for u in users:
        if (u.get("name") or "").strip().lower() == target:
            return u
    return None

def parse_index_selection(s: str, max_index: int) -> List[int]:
    """
    Parse input like:
      "2-4" -> [2,3,4]
      "2,5,8,1" -> [1,2,5,8]
      "2-4,6,8,9" -> [2,3,4,6,8,9]
    Validates indices in [1..max_index]. Returns sorted unique indices.
    """
    if not s:
        raise ValueError("No selection entered.")
    indices: set[int] = set()
    parts = [p.strip() for p in s.split(",") if p.strip()]
    if not parts:
        raise ValueError("No valid tokens found.")
    for part in parts:
        if "-" in part:
            a, b = part.split("-", 1)
            i = int(a.strip())
            j = int(b.strip())
            if i > j:
                i, j = j, i
            if i < 1 or j > max_index:
                raise ValueError(f"Range {i}-{j} out of bounds (1..{max_index}).")
            for k in range(i, j + 1):
                indices.add(k)
        else:
            k = int(part)
            if k < 1 or k > max_index:
                raise ValueError(f"Index {k} out of bounds (1..{max_index}).")
            indices.add(k)
    if not indices:
        raise ValueError("No valid indices selected.")
    return sorted(indices)

def select_users_multi(users: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    print_users_table(users)
    prompt = "Select user(s) by number/range/list (e.g., 2-4,6,8): "
    while True:
        raw = input(prompt).strip()
        try:
            idxs = parse_index_selection(raw, len(users))
            return [users[i - 1] for i in idxs]
        except Exception as e:
            print(f"Invalid selection: {e}")

def ip_from_str(s):
    if "/" in s:
        return ipaddress.ip_interface(s)
    return ipaddress.ip_address(s)

def next_available_interface_ip(network_obj: Dict[str, Any], existing_clients: List[Dict[str, Any]]) -> str:
    # network_obj["ip_subnet"] like "192.168.7.1/24"
    ipi = ip_from_str(network_obj["ip_subnet"])
    subnet = ipi.network
    server_ip = ipi.ip
    used = set()
    for c in existing_clients:
        ii = c.get("interface_ip")
        if ii:
            try:
                used.add(ip_from_str(ii))
            except Exception:
                pass
    for host in subnet.hosts():
        if host == server_ip:
            continue
        if host not in used:
            return str(host)
    raise RuntimeError("No free interface IP available in subnet.")

def generate_wg_keypair() -> Tuple[str, str]:
    priv = PrivateKey.generate()
    priv_b = bytes(priv)                  # 32 bytes
    pub_b = bytes(priv.public_key)        # 32 bytes
    priv_b64 = base64.b64encode(priv_b).decode()
    pub_b64  = base64.b64encode(pub_b).decode()
    return priv_b64, pub_b64

def create_wireguard_user_v2(session: requests.Session, urls: Dict[str, str],
                             network_id: str, name: str, interface_ip: str, public_key: str) -> Dict[str, Any]:
    # POST /proxy/network/v2/api/site/{site}/wireguard/{network_id}/users/batch
    url = f"{urls['WG_USERS_V2_BASE']}/{network_id}/users/batch"
    payload = [{
        "name": name,
        "interface_ip": interface_ip,
        "public_key": public_key
    }]
    r = vrequest(session, "POST", url, json=payload, headers={"Content-Type": "application/json"})
    r.raise_for_status()
    data = r.json()
    return data[0] if isinstance(data, list) and data else data

def extract_dns_from_network(network_obj: Dict[str, Any]) -> List[str]:
    dns = []
    seen = set()
    for k, v in (network_obj or {}).items():
        if "dns" not in k.lower():
            continue
        if isinstance(v, str) and v and is_ip_addr(v) and v not in seen:
            seen.add(v)
            dns.append(v)
        elif isinstance(v, (list, tuple)):
            for item in v:
                if isinstance(item, str) and item and is_ip_addr(item) and item not in seen:
                    seen.add(item)
                    dns.append(item)
    return dns

def build_conf(network_obj: Dict[str, Any], client_privkey_b64: str, client_interface_ip: str,
               wanip: str, allowed_ips_mode: str = "subnet",
               default_dns_ips: Optional[List[str]] = None,
               additional_allowed_ips: Optional[List[str]] = None,) -> str:
    ipi = ip_from_str(network_obj["ip_subnet"])
    server_pubkey = network_obj.get("wireguard_public_key")

    if network_obj.get("vpn_client_configuration_remote_ip_override"):
        endpoint_host = network_obj.get("vpn_client_configuration_remote_ip_override")
    else:
        if is_ip_addr(network_obj.get("wireguard_local_wan_ip")):
            endpoint_host = network_obj.get("wireguard_local_wan_ip")
        else:
            endpoint_host = wanip

    endpoint_port = network_obj.get("local_port", 51820)

    # Base AllowedIPs
    if allowed_ips_mode == "full":
        base_allowed = ["0.0.0.0/0", "::/0"]
    else:
        base_allowed = [str(ipi.network)]

    # Merge AdditionalAllowedIPs (dedup, preserve order)
    combined_allowed = []
    seen = set()
    for entry in base_allowed + (additional_allowed_ips or []):
        if entry and entry not in seen:
            seen.add(entry)
            combined_allowed.append(entry)

    # DNS resolution (network -> config default -> gateway IP)
    dns_addrs = extract_dns_from_network(network_obj)
    if not dns_addrs and default_dns_ips:
        dns_addrs = [ip for ip in default_dns_ips if is_ip_addr(ip)]
    if not dns_addrs:
        dns_addrs = [str(ipi.ip)]

    lines = []
    lines.append("[Interface]")
    lines.append(f"PrivateKey = {client_privkey_b64}")
    lines.append(f"Address = {client_interface_ip}/32")
    if dns_addrs:
        lines.append(f"DNS = {', '.join(dns_addrs)}")
    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {server_pubkey}")
    lines.append(f"Endpoint = {endpoint_host}:{endpoint_port}")
    lines.append(f"AllowedIPs = {', '.join(combined_allowed)}")
    lines.append("PersistentKeepalive = 25")
    return "\n".join(lines) + "\n"

def suggest_conf_filename(network_name: str, user_name: str) -> str:
    def sanitize(s: str) -> str:
        return (s or "").replace(" ", "-")
    return f"{sanitize(network_name)}-{sanitize(user_name)}.conf"

def delete_wireguard_user(session: requests.Session, urls: Dict[str, str], network_id: str, user_ids: List[str]) -> bool:
    url = f"{urls['WG_USERS_V2_BASE']}/{network_id}/users/batch_delete"
    r = vrequest(session, "POST", url, json=user_ids)
    if 200 <= r.status_code < 300:
        return True
    try:
        detail = r.text
    except Exception:
        detail = ""
    raise requests.HTTPError(f"batch_delete failed: {r.status_code} {detail}", response=r)

def get_session_and_urls() -> Tuple[Dict[str, Any], Dict[str, str], requests.Session]:
    cfg = load_config(CONFIG_PATH)
    urls = build_urls(cfg["gateway"], cfg["site_id"])

    # Prompt for password if empty in config (prompt to stderr so it shows in -q)
    if not cfg["password"]:
        import getpass
        prompt = f"Password for {cfg['username']}@{cfg['gateway']}: "
        try:
            pwd = getpass.getpass(prompt, stream=sys.stderr)
        except Exception:
            # Fallback without stream param
            pwd = getpass.getpass(prompt)
        cfg["password"] = pwd

    s = requests.Session()
    s.verify = cfg["verify_tls"]
    s.headers.update({"Content-Type": "application/json"})
    return cfg, urls, s

def choose_network_flow(s: requests.Session, cfg: Dict[str, Any], urls: Dict[str, str], network_selector: Optional[str]) -> Dict[str, Any]:
    vprint(colorize("Fetching networks...", C_REQ))
    wg_networks = list_wireguard_networks(s, urls)
    if not wg_networks:
        raise RuntimeError("No WireGuard remote-user VPN networks found.")

    # 1) Explicit CLI selector has highest priority
    if network_selector:
        try:
            return resolve_network_selector(wg_networks, network_selector)
        except ValueError as e:
            print(f"{e}\nShowing available networks for selection instead.")
            return select_network(wg_networks)

    # 2) Fallback to config default if provided
    cfg_default = cfg.get("default_wg_network_name")
    if cfg_default:
        try:
            return resolve_network_selector(wg_networks, cfg_default)
        except ValueError:
            print(f"DefaultWGnetworkName '{cfg_default}' not found. Please select from the list below.")

    # 3) Otherwise show selection UI
    return select_network(wg_networks)

def resolve_save_path(suggested_filename: str,
                      save_arg: Optional[object],
                      default_folder: Optional[Path]) -> Optional[Path]:
    if save_arg is None:
        return None
    if save_arg is True:
        base = default_folder if default_folder else Path.cwd()
        return base / suggested_filename
    if isinstance(save_arg, str):
        p = Path(save_arg).expanduser()
        if p.suffix:
            return p
        return p / suggested_filename
    return None

def maybe_write_conf(out_path: Optional[Path], conf_text: str, force_overwrite: bool):
    if not out_path:
        return
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists() and not force_overwrite:
        print(f"Refusing to overwrite existing file: {out_path}\nUse --force to overwrite.", file=sys.stderr)
        sys.exit(1)
    with out_path.open("w", encoding="utf-8") as f:
        f.write(conf_text)
    print(f"Saved WireGuard config to: {out_path}")

def run_list_flow(network_selector: Optional[str]):
    cfg, urls, s = get_session_and_urls()
    print(f"Controller: {urls['BASE']}")
    print("Logging in...")
    login(s, urls, cfg["username"], cfg["password"])
    selected = choose_network_flow(s, cfg, urls, network_selector)
    net_name = selected.get("name") or selected.get("display_name") or selected.get("_id")
    net_id = selected.get("_id")
    print(f"\nSelected network: {net_name} (id={net_id})")
    users = list_wireguard_users_v2(s, urls, net_id)
    if not users:
        print("No users found for this WireGuard network.")
        return
    print_users_table(users)

def is_duplicate_username(existing_users: List[Dict[str, Any]], candidate: str) -> bool:
    cand = (candidate or "").strip().lower()
    return any((u.get("name") or "").strip().lower() == cand for u in existing_users)

def prompt_input_with_stderr(prompt_text: str) -> str:
    """Show a prompt in quiet mode by writing to stderr; otherwise use input(prompt)."""
    if QUIET:
        sys.stderr.write(prompt_text)
        sys.stderr.flush()
        return input().strip()
    else:
        return input(prompt_text).strip()

def prompt_unique_username(existing_users: List[Dict[str, Any]], initial: Optional[str]) -> str:
    """
    Prompt until a non-empty, non-duplicate username is provided.
    In quiet mode:
      - Do NOT print tables or chatter
      - Only show the prompt (on stderr) even when duplicate is found
    """
    name = (initial or "").strip()
    while True:
        if not name:
            name = prompt_input_with_stderr("Enter new WireGuard username: ")
            continue
        if is_duplicate_username(existing_users, name):
            if QUIET:
                # Show only the question again (on stderr)
                name = prompt_input_with_stderr("Username exists. Enter a different WireGuard username: ")
            else:
                print(f"Username '{name}' already exists in this network. Existing users:")
                print_users_table(existing_users)
                name = input("Enter a different WireGuard username: ").strip()
            continue
        return name

def print_config_output(conf_text: str):
    """
    Ensure the WireGuard config text is printed even in quiet mode.
    In quiet mode, stdout may be redirected; write to ORIGINAL_STDOUT instead.
    """
    if QUIET:
        try:
            ORIGINAL_STDOUT.write(conf_text)
            ORIGINAL_STDOUT.flush()
        except Exception:
            # Fallback to stderr if needed
            sys.stderr.write(conf_text)
            sys.stderr.flush()
    else:
        print(conf_text)

def add_user_flow(username_arg: Optional[str], network_selector: Optional[str], save_arg: Optional[object], force_overwrite: bool):
    cfg, urls, s = get_session_and_urls()
    qprint(f"Controller: {urls['BASE']}")
    qprint("Logging in...")
    login(s, urls, cfg["username"], cfg["password"])

    wanip = get_wan_ip(s, urls)
    selected = choose_network_flow(s, cfg, urls, network_selector)
    net_name = selected.get("name") or selected.get("display_name") or selected.get("_id")
    net_id = selected.get("_id")
    qprint(f"\nSelected network: {net_name} (id={net_id})")

    existing_users = list_wireguard_users_v2(s, urls, net_id)

    # Username (ensure uniqueness; in -q prompt on stderr is preserved)
    new_name = prompt_unique_username(existing_users, username_arg)

    # Next IP
    qprint("Determining next available interface IP...")
    iface_ip = next_available_interface_ip(selected, existing_users)
    qprint(f"Using interface IP: {iface_ip}")

    # Keypair + create
    qprint("Generating WireGuard keypair...")
    priv_b64, pub_b64 = generate_wg_keypair()

    qprint(f"Creating user '{new_name}'...")
    created = create_wireguard_user_v2(s, urls, net_id, new_name, iface_ip, pub_b64)

    created_name = created.get("name") or new_name
    created_id = created.get("_id", "")
    created_ip = created.get("interface_ip", iface_ip)

    # Summary (suppressed in -q)
    if not QUIET:
        table = PrettyTable()
        table.field_names = ["Name", "ID", "IP Address", "Public Key (truncated)"]
        table.align["Name"] = "l"
        table.align["ID"] = "l"
        table.align["IP Address"] = "l"
        table.align["Public Key (truncated)"] = "l"
        table.add_row([created_name, created_id, created_ip, pub_b64[:16] + "..."])
        print("\nUser created")
        print(table)

    # Build config
    conf_text = build_conf(
        selected,
        priv_b64,
        created_ip,
        wanip,
        allowed_ips_mode="subnet",
        default_dns_ips=cfg["default_dns_ips"],
        additional_allowed_ips=cfg["additional_allowed_ips"],
    )

    suggested = suggest_conf_filename(net_name, created_name)

    # Print config and optional save
    if QUIET:
        # In quiet mode, only print the configuration if not saving
        if save_arg is None:
            print_config_output(conf_text)
    else:
        # Normal mode: show filename tip and the config
        print(f"\nSuggested filename: {suggested}")
        print("\nWireGuard configuration (copy/paste):")
        print(conf_text)

    # Save if requested
    out_path = resolve_save_path(
        suggested_filename=suggested,
        save_arg=save_arg,
        default_folder=cfg["default_wg_conf_folder"]
    )
    maybe_write_conf(out_path, conf_text, force_overwrite)

def delete_user_flow(usernames: Optional[List[str]], network_selector: Optional[str], force_delete: bool):
    cfg, urls, s = get_session_and_urls()
    print(f"Controller: {urls['BASE']}")
    print("Logging in...")
    login(s, urls, cfg["username"], cfg["password"])

    selected = choose_network_flow(s, cfg, urls, network_selector)
    net_name = selected.get("name") or selected.get("display_name") or selected.get("_id")
    net_id = selected.get("_id")
    print(f"\nSelected network: {net_name} (id={net_id})")

    users = list_wireguard_users_v2(s, urls, net_id)
    if not users:
        print("No users found for this WireGuard network.")
        return

    if isinstance(usernames, list) and len(usernames) > 0:
        # Delete by provided names (exact case-insensitive matches)
        to_delete: List[Dict[str, Any]] = []
        missing: List[str] = []
        seen_names = set()
        for nm in usernames:
            nm_norm = (nm or "").strip()
            if not nm_norm:
                continue
            if nm_norm.lower() in seen_names:
                continue  # dedupe provided names
            seen_names.add(nm_norm.lower())
            found = find_user_by_name(users, nm_norm)
            if found:
                to_delete.append(found)
            else:
                missing.append(nm_norm)
        if missing:
            # Print missing as error to stderr so it shows even in -q
            print("The following user names were not found in the selected network:", file=sys.stderr)
            for m in missing:
                print(f"  - {m}", file=sys.stderr)
            # The detailed list is informational; goes to stdout and thus suppressed when -q is in effect
            print("\nAvailable users are:")
            print_users_table(users)
            return
    else:
        # No names provided -> interactive multi-select (ranges/lists)
        to_delete = select_users_multi(users)

    table = PrettyTable()
    table.field_names = ["#", "Name", "ID", "IP Address"]
    table.align["Name"] = table.align["ID"] = table.align["IP Address"] = "l"
    for i, u in enumerate(to_delete, 1):
        table.add_row([i, u.get("name") or "", u.get("_id") or "", u.get("interface_ip") or ""])
    print("\nAbout to delete the following user(s):")
    print(table)

    # Confirmation: skip when --force; otherwise ensure prompt visible even in -q
    if not force_delete:
        prompt = f"Type 'yes' to confirm deletion of {len(to_delete)} user(s): "
        if QUIET:
            # Ensure the confirmation question is NOT suppressed in quiet mode
            print(prompt, file=sys.stderr, end="")
            ans = input().strip().lower()
        else:
            ans = input(prompt).strip().lower()
        if ans != "yes":
            print("Deletion cancelled.")
            return

    user_ids = [u.get("_id") for u in to_delete if u.get("_id")]
    if not user_ids:
        print("No valid user IDs found to delete.")
        return

    ok = delete_wireguard_user(s, urls, net_id, user_ids)
    if ok:
        print(f"Deleted {len(user_ids)} user(s) successfully.")
        remaining = list_wireguard_users_v2(s, urls, net_id)
        if remaining:
            print("\nRemaining users:")
            print_users_table(remaining)
        else:
            print("No users remain on this WireGuard network.")

def main():
    global VERBOSE, COLORIZE, QUIET, ORIGINAL_STDOUT
    parser = argparse.ArgumentParser(description="UniFi WireGuard helper")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-l", "--list", action="store_true",
                       help="List users (optionally select network with -n)")
    group.add_argument("-a", "--add", metavar="USERNAME",
                       help="Add user with USERNAME (optionally select network with -n)")
    # -d accepts a list (zero or more) USERNAMEs. Zero -> interactive multi-select.
    group.add_argument("-d", "--delete", nargs="*", metavar="USERNAME",
                       help="Delete user(s) by USERNAME (optionally select network with -n). If omitted, list and allow selecting multiple users (ranges/lists). For names with spaces, quote them.")
    parser.add_argument("-n", "--network", metavar="NETWORK",
                        help="Network selector: network ID (_id) or exact name (case-insensitive). If omitted, DefaultWGnetworkName from config is used when set; otherwise a selection is shown.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose mode: print API calls and responses (colored)")
    parser.add_argument("-nc", "--no-color", action="store_true",
                        help="Disable color in verbose output")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Quiet mode")
    parser.add_argument("-s", "--save", nargs="?", const=True, metavar="PATH",
                        help="Also save the generated config. Without PATH, save to current dir or DefaultWGconfFolder if set. With PATH, save to that exact file or into that directory.")
    parser.add_argument("--force", action="store_true",
                        help="Allow overwriting existing config files when saving and skip deletion confirmation prompts")

    args = parser.parse_args()
    VERBOSE = args.verbose
    COLORIZE = not args.no_color
    QUIET = args.quiet

    # Capture original stdout for selective printing under -q
    ORIGINAL_STDOUT = sys.stdout

    # Suppress stdout in quiet mode. We will explicitly print required outputs to ORIGINAL_STDOUT.
    if QUIET:
        try:
            sys.stdout = open(os.devnull, "w")
        except Exception:
            pass
        VERBOSE = False

    try:
        if args.list:
            run_list_flow(args.network)
        elif args.add is not None:
            add_user_flow(args.add, args.network, args.save, args.force)
        elif args.delete is not None:
            if len(args.delete) == 0:
                delete_user_flow(None, args.network, args.force)
            else:
                delete_user_flow(args.delete, args.network, args.force)
    except requests.HTTPError as e:
        print(f"HTTP error: {e} - {getattr(e.response, 'text', '')}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("Execution was interrupted by the user!", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()
