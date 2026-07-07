#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
System Guardian - ابزار تشخیص رفتار مشکوک، اتصالات ریموت و اسکن شبکه محلی
نویسنده: Amir (با کمک Claude)

هشدار قانونی / Legal Notice:
این ابزار فقط برای استفاده روی سیستم و شبکه‌ی خودتان (یا شبکه‌ای که مجوز اسکن آن را دارید) طراحی شده.
This tool is intended ONLY for scanning systems/networks you own or are explicitly authorized to test.
Scanning networks without permission may be illegal in your jurisdiction.

قابلیت‌ها:
  1. Process Scanner       -> پروسه‌های مشکوک در حال اجرا
  2. Startup Scanner       -> برنامه‌های اجرای خودکار (Windows Registry / Linux cron & systemd)
  3. Connection Detector   -> اتصالات ریموت فعال (کی از بیرون وصل شده)
  4. Network Scanner       -> اسکن شبکه محلی برای هاست‌های آنلاین و پورت‌های خطرناک باز

استفاده:
  python3 system_guardian.py --local          فقط اسکن لوکال سیستم (process+startup+connections)
  python3 system_guardian.py --network        فقط اسکن شبکه محلی
  python3 system_guardian.py --all            هر دو
  python3 system_guardian.py --all --report out.json   ذخیره گزارش JSON
  python3 system_guardian.py --network --cidr 192.168.1.0/24 --ports 22,80,445,3389
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import platform
import socket
import subprocess
import sys
import time
from datetime import datetime

try:
    import psutil
except ImportError:
    print("[!] پکیج psutil نصب نیست. با دستور زیر نصبش کن:")
    print("    pip install psutil")
    sys.exit(1)

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"

# ---------------------------------------------------------------------------
# رنگ‌ها برای خروجی ترمینال (اگر ترمینال ساپورت نکنه، خودکار رد می‌شه)
# ---------------------------------------------------------------------------
class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"

    @staticmethod
    def off():
        for attr in ["RED", "GREEN", "YELLOW", "CYAN", "BOLD", "END"]:
            setattr(C, attr, "")


if not sys.stdout.isatty():
    C.off()

# ---------------------------------------------------------------------------
# دیتای مرجع (heuristic) - این جایگزین دیتابیس آنتی‌ویروس واقعی نیست
# ---------------------------------------------------------------------------

SUSPICIOUS_PROCESS_NAMES = {
    "mimikatz", "nc.exe", "netcat", "ncat", "psexec", "meterpreter",
    "cobaltstrike", "beacon", "rundll32_susp", "regsvr32_susp",
    "powershell_encoded", "wannacry", "cryptolocker", "keylogger",
    "svch0st", "scvhost", "explor3r",  # typosquat ها
}

SUSPICIOUS_PATH_HINTS = (
    "temp", "tmp", "appdata\\local\\temp", "/tmp/", "downloads",
)

RISKY_REMOTE_PORTS = {
    22: "SSH",
    23: "Telnet (ناامن)",
    445: "SMB (ریسک کرم/باج‌افزار)",
    3389: "RDP (دسکتاپ ریموت ویندوز)",
    5900: "VNC",
    5901: "VNC",
    5938: "TeamViewer",
    4899: "Radmin",
    6568: "AnyDesk",
}

COMMON_SCAN_PORTS = [21, 22, 23, 25, 80, 135, 139, 443, 445, 3389, 5900, 8080]


def is_local_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# 1) Process Scanner
# ---------------------------------------------------------------------------
def scan_processes():
    print(f"\n{C.BOLD}{C.CYAN}== ۱) اسکن پروسه‌های در حال اجرا =={C.END}")
    findings = []
    for proc in psutil.process_iter(["pid", "name", "exe", "cpu_percent", "memory_percent"]):
        try:
            info = proc.info
            name = (info.get("name") or "").lower()
            exe = (info.get("exe") or "").lower()

            reasons = []
            if any(sus in name for sus in SUSPICIOUS_PROCESS_NAMES):
                reasons.append("نام پروسه در لیست مشکوک‌هاست")
            if exe and any(hint in exe for hint in SUSPICIOUS_PATH_HINTS):
                reasons.append(f"اجرا از مسیر مشکوک: {exe}")
            try:
                if proc.cpu_percent(interval=0.0) > 70:
                    reasons.append("مصرف CPU غیرعادی بالا")
            except Exception:
                pass

            if reasons:
                findings.append({
                    "pid": info.get("pid"),
                    "name": info.get("name"),
                    "exe": info.get("exe"),
                    "reasons": reasons,
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    if findings:
        for f in findings:
            print(f"{C.RED}[مشکوک]{C.END} PID={f['pid']} name={f['name']}")
            for r in f["reasons"]:
                print(f"    - {r}")
    else:
        print(f"{C.GREEN}[OK]{C.END} هیچ پروسه مشکوکی (طبق قوانین heuristic) پیدا نشد.")

    print(f"{C.YELLOW}توجه: این چک جایگزین آنتی‌ویروس واقعی نیست، فقط رفتار مشکوک رو نشون می‌ده.{C.END}")
    return findings


# ---------------------------------------------------------------------------
# 2) Startup Scanner
# ---------------------------------------------------------------------------
def scan_startup():
    print(f"\n{C.BOLD}{C.CYAN}== ۲) اسکن برنامه‌های اجرای خودکار (Startup) =={C.END}")
    entries = []

    if IS_WINDOWS:
        try:
            import winreg
            keys_to_check = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            ]
            for hive, path in keys_to_check:
                try:
                    key = winreg.OpenKey(hive, path)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            entries.append({"name": name, "command": value, "source": path})
                            i += 1
                        except OSError:
                            break
                except FileNotFoundError:
                    continue
        except ImportError:
            print(f"{C.YELLOW}winreg در دسترس نیست.{C.END}")
    elif IS_LINUX:
        # کرون‌جاب‌های کاربر فعلی
        try:
            out = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5)
            if out.returncode == 0 and out.stdout.strip():
                for line in out.stdout.strip().splitlines():
                    if line.strip() and not line.strip().startswith("#"):
                        entries.append({"name": "cron", "command": line.strip(), "source": "crontab -l"})
        except Exception:
            pass
        # systemd user services (اگر وجود داشته باشه)
        systemd_dir = os.path.expanduser("~/.config/systemd/user")
        if os.path.isdir(systemd_dir):
            for f in os.listdir(systemd_dir):
                entries.append({"name": f, "command": os.path.join(systemd_dir, f), "source": "systemd --user"})
    else:
        print(f"{C.YELLOW}این پلتفرم ({platform.system()}) پشتیبانی نمی‌شه.{C.END}")

    if entries:
        for e in entries:
            print(f"{C.YELLOW}[Startup]{C.END} {e['name']} -> {e['command']}  (منبع: {e['source']})")
        print(f"{C.YELLOW}هرکدوم از این‌ها رو نمی‌شناسی، بررسی‌شون کن.{C.END}")
    else:
        print(f"{C.GREEN}[OK]{C.END} هیچ آیتم Startup ثبت‌شده‌ای پیدا نشد.")

    return entries


# ---------------------------------------------------------------------------
# 3) Remote Connection Detector
# ---------------------------------------------------------------------------
def scan_connections():
    print(f"\n{C.BOLD}{C.CYAN}== ۳) اسکن اتصالات فعال شبکه (کی به سیستم وصله) =={C.END}")
    findings = []
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        print(f"{C.YELLOW}برای دیدن همه‌ی اتصالات نیاز به دسترسی ادمین/روت داری. با sudo اجرا کن.{C.END}")
        conns = []

    for c in conns:
        if c.status != psutil.CONN_ESTABLISHED:
            continue
        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
        raddr_ip = c.raddr.ip if c.raddr else None
        raddr_port = c.raddr.port if c.raddr else None

        if not raddr_ip:
            continue

        risky = raddr_port in RISKY_REMOTE_PORTS or c.laddr.port in RISKY_REMOTE_PORTS
        external = not is_local_ip(raddr_ip)

        if risky or external:
            proc_name = "-"
            try:
                if c.pid:
                    proc_name = psutil.Process(c.pid).name()
            except Exception:
                pass

            note = []
            if external:
                note.append("IP خارجی/غیر-لوکال")
            if c.laddr.port in RISKY_REMOTE_PORTS:
                note.append(f"پورت محلی حساس: {RISKY_REMOTE_PORTS[c.laddr.port]}")
            if raddr_port in RISKY_REMOTE_PORTS:
                note.append(f"پورت مقصد حساس: {RISKY_REMOTE_PORTS[raddr_port]}")

            findings.append({
                "local": laddr,
                "remote": f"{raddr_ip}:{raddr_port}",
                "pid": c.pid,
                "process": proc_name,
                "notes": note,
            })

    if findings:
        for f in findings:
            print(f"{C.RED}[اتصال]{C.END} {f['local']}  <-->  {f['remote']}  "
                  f"(پروسه: {f['process']}, PID: {f['pid']})")
            for n in f["notes"]:
                print(f"    - {n}")
        print(f"{C.YELLOW}اگه این IP یا برنامه رو نمی‌شناسی، احتمال داره یکی از راه دور وصل باشه.{C.END}")
    else:
        print(f"{C.GREEN}[OK]{C.END} هیچ اتصال ریموت مشکوکی در حال حاضر پیدا نشد.")

    return findings


# ---------------------------------------------------------------------------
# 4) Local Network Scanner
# ---------------------------------------------------------------------------
def get_local_subnet():
    """حدس زدن ساب‌نت محلی از روی IP خود سیستم (فرض /24)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        net = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        return str(net)
    except Exception:
        return "192.168.1.0/24"


def check_port(ip, port, timeout=0.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            return result == 0
    except Exception:
        return False


def scan_host(ip, ports):
    open_ports = []
    for p in ports:
        if check_port(str(ip), p):
            open_ports.append(p)
    return str(ip), open_ports


def scan_network(cidr=None, ports=None, max_workers=100):
    print(f"\n{C.BOLD}{C.CYAN}== ۴) اسکن شبکه محلی =={C.END}")
    print(f"{C.YELLOW}هشدار: فقط روی شبکه‌ای که خودت صاحبشی یا مجوز اسکن داری استفاده کن.{C.END}")

    cidr = cidr or get_local_subnet()
    ports = ports or COMMON_SCAN_PORTS

    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        print(f"{C.RED}CIDR نامعتبر: {e}{C.END}")
        return []

    hosts = list(network.hosts())
    if len(hosts) > 1024:
        print(f"{C.YELLOW}رنج {cidr} خیلی بزرگه ({len(hosts)} هاست)، فقط ۱۰۲۴ تای اول چک می‌شه.{C.END}")
        hosts = hosts[:1024]

    print(f"در حال اسکن {cidr}  ({len(hosts)} آدرس) روی پورت‌های {ports} ...")

    results = []
    start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(scan_host, ip, ports): ip for ip in hosts}
        for fut in concurrent.futures.as_completed(futures):
            ip, open_ports = fut.result()
            if open_ports:
                results.append({"ip": ip, "open_ports": open_ports})

    elapsed = time.time() - start
    print(f"اسکن تمام شد در {elapsed:.1f} ثانیه.")

    if results:
        for r in sorted(results, key=lambda x: x["ip"]):
            risky_open = [p for p in r["open_ports"] if p in RISKY_REMOTE_PORTS]
            tag = f"{C.RED}[ریسک بالا]{C.END}" if risky_open else f"{C.GREEN}[آنلاین]{C.END}"
            print(f"{tag} {r['ip']}  پورت‌های باز: {r['open_ports']}")
            for rp in risky_open:
                print(f"    - {RISKY_REMOTE_PORTS[rp]} باز است (پورت {rp})")
    else:
        print(f"{C.GREEN}هیچ هاست آنلاینی با پورت‌های چک‌شده پیدا نشد "
              f"(یا ICMP/پورت‌ها فیلترن).{C.END}")

    return results


# ---------------------------------------------------------------------------
# Report / Main
# ---------------------------------------------------------------------------
def save_report(report, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"\n{C.GREEN}گزارش ذخیره شد در:{C.END} {path}")


def main():
    parser = argparse.ArgumentParser(
        description="System Guardian - ابزار تشخیص رفتار مشکوک و اسکن شبکه (فقط برای سیستم/شبکه خودتان)"
    )
    parser.add_argument("--local", action="store_true", help="اسکن لوکال: پروسه‌ها + startup + اتصالات")
    parser.add_argument("--network", action="store_true", help="اسکن شبکه محلی")
    parser.add_argument("--all", action="store_true", help="اجرای همه‌ی اسکن‌ها")
    parser.add_argument("--cidr", type=str, default=None, help="مثال: 192.168.1.0/24")
    parser.add_argument("--ports", type=str, default=None, help="مثال: 22,80,443,3389")
    parser.add_argument("--report", type=str, default=None, help="مسیر فایل خروجی JSON")

    args = parser.parse_args()

    if not (args.local or args.network or args.all):
        args.all = True  # پیش‌فرض: همه چیز

    ports = None
    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]

    print(f"{C.BOLD}{C.CYAN}"
          f"System Guardian - شروع اسکن ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})"
          f"{C.END}")
    print(f"سیستم‌عامل: {platform.system()} {platform.release()}")

    report = {"timestamp": datetime.now().isoformat(), "platform": platform.platform()}

    if args.local or args.all:
        report["suspicious_processes"] = scan_processes()
        report["startup_entries"] = scan_startup()
        report["remote_connections"] = scan_connections()

    if args.network or args.all:
        report["network_scan"] = scan_network(cidr=args.cidr, ports=ports)

    print(f"\n{C.BOLD}{C.CYAN}== خلاصه =={C.END}")
    n_proc = len(report.get("suspicious_processes", []))
    n_conn = len(report.get("remote_connections", []))
    n_net = len(report.get("network_scan", []))
    print(f"پروسه‌های مشکوک: {n_proc} | اتصالات ریموت مشکوک: {n_conn} | هاست‌های شبکه پیدا شده: {n_net}")

    if args.report:
        save_report(report, args.report)


if __name__ == "__main__":
    main()
