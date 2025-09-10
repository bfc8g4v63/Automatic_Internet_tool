### IP_Scan_Set_CLI.py
## IP 網際網路掃描與設定工具（命令列版）
import ctypes
import platform
import subprocess
import socket
import ipaddress
import concurrent.futures
import sys
import os
from datetime import datetime

def safe_decode(b: bytes) -> str:
    for enc in ("utf-8", "cp950", "mbcs", "latin-1"):
        try:
            return b.decode(enc)
        except Exception:
            continue
    return b.decode("latin-1", errors="replace")

def run_cmdline(cmdline: str) -> str:
    p = subprocess.run(["cmd", "/c", cmdline], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return safe_decode(p.stdout)

def wait_at_end():
    try:
        input("\n按 Enter 結束")
        return
    except Exception:
        pass
    try:
        ctypes.windll.user32.MessageBoxW(None, "按「確定」結束。", "IP Scan Set Tool", 0x00000040)
    except Exception:
        pass

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def elevate_if_needed():
    if platform.system().lower() != "windows":
        return False
    if is_admin():
        return False
    prog = sys.executable
    params = ""
    if getattr(sys, "frozen", False):
        pass
    else:
        params = f'"{sys.argv[0]}"'
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", prog, params, None, 1)
        return True
    except Exception:
        return False

def ping_once(ip: str, timeout_ms: int) -> bool:
    is_windows = platform.system().lower().startswith("win")
    if is_windows:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r.returncode == 0

def scan_subnet(cidr: str, timeout_ms: int, workers: int, exclude=set()):
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in net.hosts()]
    if exclude:
        hosts = [h for h in hosts if h not in exclude]
    used, free = [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        fut_map = {ex.submit(ping_once, ip, timeout_ms): ip for ip in hosts}
        for fut in concurrent.futures.as_completed(fut_map):
            ip = fut_map[fut]
            alive = fut.result()
            (used if alive else free).append(ip)
    key = lambda x: tuple(map(int, x.split(".")))
    used.sort(key=key)
    free.sort(key=key)
    return used, free

def list_nics():
    try:
        esc_cmd = "(Get-NetAdapter -Physical | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceAlias -notmatch 'Loopback' -and $_.InterfaceAlias -notmatch 'Wi-?Fi|WLAN'} | Where-Object {$_.InterfaceAlias -match 'Ethernet|乙太|以太'} | Select-Object -ExpandProperty InterfaceAlias)"
        ps = ["powershell", "-NoProfile", "-Command", esc_cmd]
        out = subprocess.check_output(ps)
        text = safe_decode(out).strip()
        names = [ln.strip() for ln in text.splitlines() if ln.strip()]
        if names:
            return names
    except Exception:
        pass
    try:
        esc_cmd = "(Get-NetIPInterface -AddressFamily IPv4 | Where-Object {$_.InterfaceOperationalStatus -eq 'Up' -and $_.InterfaceAlias -notmatch 'Loopback|Wi-?Fi|WLAN'} | Select-Object -ExpandProperty InterfaceAlias)"
        ps = ["powershell", "-NoProfile", "-Command", esc_cmd]
        out = subprocess.check_output(ps)
        text = safe_decode(out).strip()
        names = [ln.strip() for ln in text.splitlines() if ln.strip()]
        if names:
            return names
    except Exception:
        pass
    try:
        out = subprocess.check_output(["netsh", "interface", "ipv4", "show", "interfaces"])
        text = safe_decode(out)
    except Exception:
        text = None
    if not text:
        return []
    names = []
    for ln in text.splitlines():
        if not ln.strip() or "Idx" in ln or "----" in ln:
            continue
        parts = ln.strip().split()
        if len(parts) >= 5:
            alias = " ".join(parts[4:])
            a = alias.lower()
            if ("loopback" in a) or ("wi-fi" in a) or ("wlan" in a):
                continue
            names.append(alias)
    return names

def choose_iface_interactively():
    nics = list_nics()
    if not nics:
        print("找不到任何可用的有線 IPv4 介面")
        return None
    print("\n可用網卡（輸入編號或完整名稱；直接 Enter 取用 1）：")
    for i, n in enumerate(nics, 1):
        print(f"{i:3d}. {n}")
    s = input("\n請輸入網卡編號或名稱：").strip()
    if not s:
        return nics[0]
    if s.isdigit():
        idx = int(s)
        if 1 <= idx <= len(nics):
            return nics[idx - 1]
        print("編號超出範圍")
        return None
    if s in nics:
        return s
    print("名稱不在清單中")
    return None

def set_static(ip: str, mask: str, gateway: str, iface: str) -> str:
    cmd = f'netsh interface ipv4 set address name="{iface}" source=static address={ip} mask={mask} gateway={gateway} gwmetric=1'
    return run_cmdline(cmd)

def set_dns(primary: str, secondary: str, iface: str):
    o1 = run_cmdline(f'netsh interface ipv4 set dnsservers name="{iface}" source=static address={primary} register=primary validate=yes')
    o2 = ""
    if secondary:
        o2 = run_cmdline(f'netsh interface ipv4 add dnsservers name="{iface}" address={secondary} index=2 validate=yes')
    return o1, o2

def set_dhcp(iface: str):
    o1 = run_cmdline(f'netsh interface ipv4 set address name="{iface}" source=dhcp')
    o2 = run_cmdline(f'netsh interface ipv4 set dnsservers name="{iface}" source=dhcp')
    return o1, o2

def add_ip_alias(iface: str, ip: str, mask: str):
    return run_cmdline(f'netsh interface ipv4 add address name="{iface}" address={ip} mask={mask}')

def del_ip_alias(iface: str, ip: str):
    return run_cmdline(f'netsh interface ipv4 delete address name="{iface}" address={ip}')

def get_if_index(iface: str):
    txt = run_cmdline('netsh interface ipv4 show interfaces')
    idx = None
    for ln in txt.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith('Idx') or ln.startswith('---'):
            continue
        parts = ln.split()
        if len(parts) >= 5:
            try:
                cand_idx = int(parts[0])
            except Exception:
                continue
            name = " ".join(parts[4:])
            if name == iface:
                idx = cand_idx
                break
    return idx

def add_host_route(dst_ip: str, gw: str, if_index: int, metric: int = 5) -> str:
    return run_cmdline(f'route add {dst_ip} mask 255.255.255.255 {gw} metric {metric} IF {if_index}')

def del_host_route(dst_ip: str, if_index: int) -> str:
    return run_cmdline(f'route delete {dst_ip} IF {if_index}')

def ping_from(src: str, dst: str, timeout_ms: int) -> bool:
    if platform.system().lower().startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), "-S", src, dst]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), dst]
    r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r.returncode == 0

def tcp_connect_from(src_ip: str, dst_ip: str, port: int, timeout_ms: int) -> bool:
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((src_ip, 0))
        s.settimeout(max(0.001, timeout_ms / 1000))
        s.connect((dst_ip, port))
        s.close()
        return True
    except Exception:
        try:
            if s:
                s.close()
        except Exception:
            pass
        return False

def _is_ipv4(s: str) -> bool:
    try:
        socket.inet_aton(s)
        return True
    except Exception:
        return False

def get_iface_dns_servers(iface: str):
    try:
        esc = iface.replace("'", "''")
        cmd = f"(Get-DnsClientServerAddress -InterfaceAlias '{esc}' -AddressFamily IPv4).ServerAddresses"
        ps = ["powershell", "-NoProfile", "-Command", cmd]
        out = subprocess.check_output(ps)
        text = safe_decode(out).strip()
        addrs = [ln.strip() for ln in text.splitlines() if ln.strip()]
        return [a for a in addrs if _is_ipv4(a)]
    except Exception:
        pass
    txt = run_cmdline(f'netsh interface ipv4 show dnsservers name="{iface}"')
    ips = []
    for ln in txt.splitlines():
        s = ln.strip().split()[:1]
        if s and _is_ipv4(s[0]):
            ips.append(s[0])
    return ips

def get_system_proxy_ip_port():
    txt = run_cmdline("netsh winhttp show proxy")
    cand = []
    for ln in txt.splitlines():
        ls = ln.strip().lower()
        if "proxy server(s)" in ls and "=" in ln:
            parts = ln.split(":", 1)[1]
            for seg in parts.split(";"):
                seg = seg.strip()
                if "=" in seg:
                    seg = seg.split("=", 1)[1].strip()
                if seg.count(":") == 1:
                    host, port = seg.split(":")
                    host = host.strip()
                    port = port.strip()
                    if _is_ipv4(host) and port.isdigit():
                        cand.append((host, int(port)))
    try:
        txt2 = run_cmdline(r'reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer')
        for ln in txt2.splitlines():
            if "ProxyServer" in ln:
                after = ln.split("REG_SZ", 1)[1].strip()
                for seg in after.split(";"):
                    seg = seg.strip()
                    if "=" in seg:
                        seg = seg.split("=", 1)[1].strip()
                    if seg.count(":") == 1:
                        host, port = seg.split(":")
                        host = host.strip()
                        port = port.strip()
                        if _is_ipv4(host) and port.isdigit():
                            cand.append((host, int(port)))
    except Exception:
        pass
    seen = set()
    res = []
    for h, p in cand:
        key = f"{h}:{p}"
        if key not in seen:
            seen.add(key)
            res.append((h, p))
    return res

def resolve_hostname_via_iface_dns(iface: str, hostname: str):
    ips = []
    try:
        esc = iface.replace("'", "''")
        cmd = (
            f"$dns=(Get-DnsClientServerAddress -InterfaceAlias '{esc}' -AddressFamily IPv4).ServerAddresses; "
            f"if($dns) {{Resolve-DnsName -Name '{hostname}' -Server $dns -Type A -ErrorAction SilentlyContinue | "
            f"Select-Object -ExpandProperty IPAddress}}"
        )
        ps = ["powershell", "-NoProfile", "-Command", cmd]
        out = subprocess.check_output(ps)
        text = safe_decode(out).strip()
        for ln in text.splitlines():
            if _is_ipv4(ln.strip()):
                ips.append(ln.strip())
    except Exception:
        pass
    if not ips:
        for d in get_iface_dns_servers(iface):
            txt = run_cmdline(f'nslookup {hostname} {d}')
            for ln in txt.splitlines():
                tok = ln.strip().split()[-1:] or []
                if tok and _is_ipv4(tok[0]):
                    ips.append(tok[0])
    seen = set()
    ret = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            ret.append(ip)
    return ret

def build_test_targets(iface: str):
    targets = []
    dns_list = get_iface_dns_servers(iface)
    for d in dns_list:
        targets.append((d, 53, f"DNS {d}:53"))
    for (ip, port) in get_system_proxy_ip_port():
        targets.append((ip, port, f"PROXY {ip}:{port}"))
    targets.extend([
        ("1.1.1.1", 443, "CF 1.1.1.1:443"),
        ("1.0.0.1", 443, "CF 1.0.0.1:443")
    ])
    seen = set()
    uniq = []
    for ip, port, label in targets:
        k = f"{ip}:{port}"
        if k not in seen:
            seen.add(k)
            uniq.append((ip, port, label))
    return uniq

def parse_targets_txt(iface: str):
    base_dir = os.path.dirname(sys.executable if getattr(sys, "frozen", False) else sys.argv[0])
    path = os.path.join(base_dir, "targets.txt")
    if not os.path.isfile(path):
        return []
    items = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            hp = parts[0]
            label = parts[1].strip() if len(parts) > 1 else parts[0]
            if hp.count(":") != 1:
                continue
            host, port = hp.split(":")
            host = host.strip()
            port = port.strip()
            if not port.isdigit():
                continue
            if _is_ipv4(host):
                items.append((host, int(port), label))
            else:
                ips = resolve_hostname_via_iface_dns(iface, host)
                for ip in ips:
                    items.append((ip, int(port), label))
    seen = set()
    ret = []
    for ip, port, label in items:
        k = f"{ip}:{port}"
        if k not in seen:
            seen.add(k)
            ret.append((ip, port, label))
    return ret

def pretest_one_ip(test_ip: str, mask: str, gateway: str, iface: str, mode: str, timeout_ms: int) -> bool:
    add_ip_alias(iface, test_ip, mask)
    try:
        if_index = get_if_index(iface)
        if if_index is None:
            return False
        ok_gw = ping_from(test_ip, gateway, timeout_ms) if gateway else True
        tgt = parse_targets_txt(iface) or build_test_targets(iface)
        ok_list = []
        for dst, port, _ in tgt:
            add_host_route(dst, gateway, if_index)
            try:
                ok_list.append(tcp_connect_from(test_ip, dst, port, timeout_ms))
            finally:
                del_host_route(dst, if_index)
        ok_inet = any(ok_list)
        if mode == "intranet":
            return ok_gw
        if mode == "internet":
            return ok_inet
        return bool(ok_gw and ok_inet)
    finally:
        del_ip_alias(iface, test_ip)

def choose_ip_interactively(candidates, default_idx=1):
    if not candidates:
        print("沒有可用 IP")
        return None
    print("\n可用 IP（輸入編號或直接輸入 IP）：")
    for i, ip in enumerate(candidates, 1):
        mark = " <= 預設" if default_idx and i == default_idx else ""
        print(f"{i:3d}. {ip}{mark}")
    while True:
        s = input("\n請輸入想設定的『編號』或『IP』：").strip()
        if not s and default_idx:
            return candidates[default_idx - 1]
        if s.isdigit():
            i = int(s)
            if 1 <= i <= len(candidates):
                return candidates[i - 1]
            print("編號超出範圍")
            continue
        try:
            ipaddress.ip_address(s)
        except ValueError:
            print("格式不是合法 IPv4")
            continue
        if s in candidates:
            return s
        print("該 IP 不在可用清單（可能已被佔用或不在掃描範圍）")

def main():
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {platform.system()} {platform.release()}")
    if platform.system().lower() != "windows":
        print("僅支援 Windows（需 netsh）")
        wait_at_end()
        return

    DEFAULT_CIDR = "192.168.131.0/24"
    DEFAULT_MASK = "255.255.255.0"
    DEFAULT_GW = "192.168.131.254"
    DEFAULT_DNS1 = "8.8.8.8"
    DEFAULT_DNS2 = ""
    TIMEOUT_MS = 900
    WORKERS = 256
    PRETEST_MODE = "internet"
    PRETEST_LIMIT = 0
    EXCLUDE_SET = {DEFAULT_GW}

    if not is_admin():
        print("需要系統管理員權限，嘗試以系統管理員重新啟動...")
        if elevate_if_needed():
            return
        print("使用者拒絕或提權失敗，無法繼續。")
        wait_at_end()
        return

    nics = list_nics()
    if not nics:
        print("找不到任何可用的有線 IPv4 介面")
        wait_at_end()
        return
    print("\n可用網卡（輸入編號或完整名稱；直接 Enter 取用 1）：")
    for i, n in enumerate(nics, 1):
        print(f"{i:3d}. {n}")
    s = input("\n請輸入網卡編號或名稱：").strip()
    if not s:
        iface = nics[0]
    elif s.isdigit() and 1 <= int(s) <= len(nics):
        iface = nics[int(s) - 1]
    elif s in nics:
        iface = s
    else:
        print("未選擇有線網卡，結束")
        wait_at_end()
        return

    targets_show = parse_targets_txt(iface) or build_test_targets(iface)
    print("\n將使用下列測試目標（任一成功即判定可上外網）：")
    for _, _, label in targets_show:
        print("  -", label)

    print(f"\n掃描 {DEFAULT_CIDR}（排除: {', '.join(sorted(EXCLUDE_SET)) if EXCLUDE_SET else '無'}）")
    used, free = scan_subnet(DEFAULT_CIDR, TIMEOUT_MS, WORKERS, exclude=EXCLUDE_SET)
    print(f"已使用: {len(used)}  可用: {len(free)}")

    print(f"\n進行預測試（模式: {PRETEST_MODE}，全部候選；暫掛次要 IP + 臨時主機路由，不變更既有設定）...")
    candidates = free[:PRETEST_LIMIT] if PRETEST_LIMIT > 0 else free
    passed = []
    for ip in candidates:
        ok = pretest_one_ip(ip, DEFAULT_MASK, DEFAULT_GW, iface, PRETEST_MODE, TIMEOUT_MS)
        print(f"  {ip}: {'PASS' if ok else 'FAIL'}")
        if ok:
            passed.append(ip)

    if not passed:
        print("\n預測試沒有通過的 IP。")
        print("建議：")
        print("1) 在 EXE 同資料夾新增 targets.txt，填入公司 Proxy 或一定允許直連的 IP:Port（可寫主機名）。")
        print("2) 或改成 intranet 模式（僅驗證 Gateway 可達）。")
        wait_at_end()
        return

    print(f"\n預測試通過: {len(passed)} 個")
    chosen_ip = choose_ip_interactively(passed, default_idx=1)
    if not chosen_ip:
        print("未選擇 IP，結束")
        wait_at_end()
        return

    print(f"\n設定 {iface} => {chosen_ip} / {DEFAULT_MASK}  gw {DEFAULT_GW}")
    r1 = set_static(chosen_ip, DEFAULT_MASK, DEFAULT_GW, iface)
    print(r1.strip())
    print(f"設定 DNS => {DEFAULT_DNS1}{(' , ' + DEFAULT_DNS2) if DEFAULT_DNS2 else ''}")
    d1, d2 = set_dns(DEFAULT_DNS1, DEFAULT_DNS2, iface)
    print(d1.strip())
    if d2:
        print(d2.strip())

    print("\n=== 外網測試（含強制路由） ===")
    for host in ["8.8.8.8", "1.1.1.1"]:
        ok = ping_once(host, TIMEOUT_MS)
        print(f"ICMP {host}: {'OK' if ok else 'FAIL'}")
    try:
        g_ip = socket.gethostbyname("www.google.com")
    except Exception:
        g_ip = None
    ok_google = ping_once(g_ip, TIMEOUT_MS) if g_ip else False
    print(f"ICMP www.google.com ({g_ip if g_ip else 'resolve fail'}): {'OK' if ok_google else 'FAIL'}")

    if_index = get_if_index(iface)
    for dst, port, label in targets_show:
        add_host_route(dst, DEFAULT_GW, if_index)
        try:
            ok = tcp_connect_from(chosen_ip, dst, port, TIMEOUT_MS)
        finally:
            del_host_route(dst, if_index)
        print(f"{label}: {'OK' if ok else 'FAIL'}")

    wait_at_end()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("\n發生未預期錯誤：", e)
        import traceback
        traceback.print_exc()
        wait_at_end()