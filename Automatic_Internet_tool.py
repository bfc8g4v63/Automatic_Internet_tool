### Automatic_Internet_tool.py
## 網際網路掃描與設定工具（命令列版）
import ctypes
import platform
import subprocess
import socket
import concurrent.futures
import sys
import os
from datetime import datetime

# 狀態定義（中文）
STATUS_ZH = {
    "FREE": "可用",
    "OCCU": "已佔用",
    "LAN_OK": "內網可通",
    "WAN_OK": "可上網",
    "FAIL": "不通"
}

# 可調常數
DEFAULT_MASK = "255.255.255.0"
DEFAULT_GW_LAST = 254
DEFAULT_TIMEOUT_MS = 800
DEFAULT_WORKERS = 64
PRETEST_MODE = "mixed"   # 可選: gateway_only / internet / mixed / none
PRETEST_LIMIT = 2        # internet/mixed 模式下最多測幾個目標
INCLUDE_WIFI = True
PRETEST_TARGETS = [
    ("8.8.8.8", 53, "8.8.8.8:53 DNS"),
    ("1.1.1.1", 443, "1.1.1.1:443 HTTPS"),
    ("9.9.9.9", 53, "9.9.9.9:53 DNS"),
    ("1.0.0.1", 443, "1.0.0.1:443 HTTPS"),
]

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

def relaunch_elevated_new_console():
    if platform.system().lower() != "windows":
        return False
    if is_admin():
        return False
    script = os.path.abspath(sys.argv[0])
    pyexe = os.path.abspath(sys.executable)
    params = f'/c start "" "{pyexe}" "{script}" --elevated'
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", "cmd.exe", params, None, 1)
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

def scan_subnet_range(net_prefix: str, start: int, end: int, timeout_ms: int, workers: int, exclude=set()):
    hosts = [f"{net_prefix}.{i}" for i in range(start, end + 1)]
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
        if INCLUDE_WIFI:
            esc_cmd = "(Get-NetAdapter -Physical | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceAlias -notmatch 'Loopback'} | Select-Object -ExpandProperty InterfaceAlias)"
        else:
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
        if INCLUDE_WIFI:
            esc_cmd = "(Get-NetIPInterface -AddressFamily IPv4 | Where-Object {$_.InterfaceOperationalStatus -eq 'Up' -and $_.InterfaceAlias -notmatch 'Loopback'} | Select-Object -ExpandProperty InterfaceAlias)"
        else:
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
            if ("loopback" in a) or ((not INCLUDE_WIFI) and ("wi-fi" in a or "wlan" in a)):
                continue
            names.append(alias)
    return names

def set_static(ip: str, mask: str, gateway: str, iface: str) -> str:
    cmd = f'netsh interface ipv4 set address name="{iface}" source=static address={ip} mask={mask} gateway={gateway} gwmetric=1'
    return run_cmdline(cmd)

def set_dns(primary: str, secondary: str, iface: str):
    o1 = run_cmdline(f'netsh interface ipv4 set dnsservers name="{iface}" source=static address={primary} register=primary validate=yes')
    o2 = ""
    if secondary:
        o2 = run_cmdline(f'netsh interface ipv4 add dnsservers name="{iface}" address={secondary} index=2 validate=yes')
    return o1, o2

def choose_iface_interactively():
    nics = list_nics()
    if not nics:
        print("找不到任何可用的 IPv4 介面")
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

def build_test_targets():
    return list(PRETEST_TARGETS)

def pretest_one_ip(test_ip: str, mask: str, gateway: str, iface: str, timeout_ms: int):
    """先測內網，再測外網，回傳 (狀態, 內網可通?, 外網可通?)"""
    add_ip_alias(iface, test_ip, mask)
    try:
        if_index = get_if_index(iface)
        if if_index is None:
            return STATUS_ZH["FAIL"], False, False

        # 內網檢查：能否 ping gateway
        lan_ok = ping_once(gateway, timeout_ms)
        if not lan_ok:
            return STATUS_ZH["FREE"], False, False

        # 外網檢查
        wan_ok = False
        targets = build_test_targets()
        tested = 0
        for dst, port, label in targets:
            add_host_route(dst, gateway, if_index)
            try:
                ok = tcp_connect_from(test_ip, dst, port, timeout_ms)
            finally:
                del_host_route(dst, if_index)
            tested += 1
            if ok:
                wan_ok = True
                break
            if PRETEST_LIMIT and tested >= PRETEST_LIMIT:
                break

        if wan_ok:
            return STATUS_ZH["WAN_OK"], True, True
        else:
            return STATUS_ZH["LAN_OK"], True, False

    finally:
        del_ip_alias(iface, test_ip)

def ask_segment():
    while True:
        seg = input("\n請輸入網段數字（例如 131，將掃描 192.168.<X>.2~253）：").strip()
        if seg.isdigit() and 0 <= int(seg) <= 255:
            return int(seg)
        print("請輸入 0~255 的數字。")

def is_valid_host_in_segment(ip: str, net_prefix: str):
    if not ip.count(".") == 3:
        return False
    if not ip.startswith(f"{net_prefix}."):
        return False
    try:
        last = int(ip.split(".")[-1])
    except Exception:
        return False
    return 2 <= last <= 253

def main():
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {platform.system()} {platform.release()}")
    if platform.system().lower() != "windows":
        print("僅支援 Windows（需 netsh）")
        wait_at_end()
        return

    if not is_admin():
        if relaunch_elevated_new_console():
            return
        print("請以系統管理員身分執行再重試。")
        wait_at_end()
        return

    TIMEOUT_MS = DEFAULT_TIMEOUT_MS
    WORKERS = DEFAULT_WORKERS
    iface = choose_iface_interactively()
    if not iface:
        wait_at_end()
        return

    while True:
        seg = ask_segment()
        net_prefix = f"192.168.{seg}"
        gateway = f"{net_prefix}.{DEFAULT_GW_LAST}"
        exclude = {f"{net_prefix}.1", f"{net_prefix}.{DEFAULT_GW_LAST}"}
        print(f"\n掃描 {net_prefix}.2 ~ {net_prefix}.253（排除 .1 與 .{DEFAULT_GW_LAST}）")

        used, free = scan_subnet_range(net_prefix, 2, 253, TIMEOUT_MS, WORKERS, exclude=exclude)

        # 表頭
        print("\nIP 位址            使用狀態   內網   外網")
        print("----------------------------------------------")

        all_results = []
        for ip in used:
            all_results.append((ip, STATUS_ZH["OCCU"], True, None))
            print(f"{ip:16} {STATUS_ZH['OCCU']:<6}  ✔     -")

        passed = []
        for ip in free:
            status, lan_ok, wan_ok = pretest_one_ip(ip, DEFAULT_MASK, gateway, iface, TIMEOUT_MS)
            all_results.append((ip, status, lan_ok, wan_ok))
            lan_str = "✔" if lan_ok else "✘"
            wan_str = "✔" if wan_ok else "✘"
            print(f"{ip:16} {status:<6}  {lan_str}     {wan_str}")
            if status in (STATUS_ZH["LAN_OK"], STATUS_ZH["WAN_OK"]):
                passed.append(ip)

        print("\n統計：")
        print(f"  已佔用：{len(used)}")
        print(f"  可用/內網：{len([r for r in all_results if r[1]==STATUS_ZH['LAN_OK']])}")
        print(f"  可上網：{len([r for r in all_results if r[1]==STATUS_ZH['WAN_OK']])}")
        print(f"  完全不通：{len([r for r in all_results if r[1]==STATUS_ZH['FAIL']])}")

        if passed:
            print(f"\n此網段發現 {len(passed)} 個『可用』IP。")
            for i, ip in enumerate(passed, 1):
                print(f"{i:3d}. {ip}")

            sel = input("\n請輸入要套用的『編號』（直接 Enter 取消設定）：").strip()
            if sel.isdigit():
                idx = int(sel)
                if 1 <= idx <= len(passed):
                    chosen = passed[idx - 1]
                    print(f"\n正在套用 IP {chosen} ...")
                    print(set_static(chosen, DEFAULT_MASK, gateway, iface))
                    o1, o2 = set_dns("8.8.8.8", "1.1.1.1", iface)
                    if o1.strip():
                        print(o1.strip())
                    if o2.strip():
                        print(o2.strip())
                    print("套用完成。")
                    wait_at_end()
                    return
                else:
                    print("輸入編號超出範圍，取消設定。")
            else:
                print("未輸入有效編號，取消設定。")

        else:
            print("\n此網段沒有『可用』IP。")

        ans = input("\n是否要改掃其他網段？(y/n)：").strip().lower()
        if ans != "y":
            wait_at_end()
            return

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("\n發生未預期錯誤：", e)
        import traceback
        traceback.print_exc()
        wait_at_end()