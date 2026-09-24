"""PID 1 for synthetic browser qualification only."""
import ctypes
import os
import subprocess
import time
from pathlib import Path

environment = {
    "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
    "HOME": "/home/pwuser",
    "PYTHONPATH": "/opt/shadow:/opt/shadow-deps",
    "PLAYWRIGHT_BROWSERS_PATH": "/ms-playwright",
    "PYTHONDONTWRITEBYTECODE": "1",
    "XDG_CONFIG_HOME": "/opt/shadow/config",
    "XDG_CACHE_HOME": "/home/pwuser/.cache",
    "XDG_DATA_HOME": "/home/pwuser/.local/share",
    "DISPLAY": ":0",
}
try:
    nss = Path("/home/pwuser/.local/share/pki/nssdb")
    nss.mkdir(parents=True, mode=0o700)
    for directory in (nss, nss.parent, nss.parent.parent, nss.parent.parent.parent):
        os.chown(directory, 1001, 1001)
    for arguments in (["-N", "--empty-password"], ["-A", "-n", "Shadow synthetic fixture", "-t", "C,,", "-i", "/opt/shadow/fixture-ca.pem"]):
        subprocess.run(["/usr/bin/certutil", "-d", "sql:" + str(nss)] + arguments,
                       env=environment, user=1001, group=1001, extra_groups=[], check=True)
    subprocess.run(["/usr/lib/systemd/systemd-udevd", "--daemon", "--resolve-names=never"], check=True)
    subprocess.run(["/usr/bin/udevadm", "trigger", "--action=add"], check=True)
    subprocess.run(["/usr/bin/udevadm", "settle", "--timeout=5"], check=True)
    display = subprocess.Popen(["/usr/lib/xorg/Xorg", ":0", "-config", "/opt/shadow/xorg.conf", "-logfile", "/tmp/Xorg.log", "-nolisten", "tcp", "-noreset", "-ac", "vt1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        if Path("/tmp/.X11-unix/X0").exists():
            break
        if display.poll() is not None:
            print(Path("/tmp/Xorg.log").read_text()[-5000:], flush=True)
            raise RuntimeError("synthetic_display_failed")
        time.sleep(0.1)
    print("BROWSER_PRIVATE_DISPLAY=ready", flush=True)
    subprocess.run(["/usr/bin/python3", "/opt/shadow/browser_probe.py"],
                   env=environment, user=1001, group=1001, extra_groups=[], start_new_session=True, timeout=45)
finally:
    print("SHADOW_BROWSER_END", flush=True)
    os.sync()
    ctypes.CDLL(None).reboot(0x4321FEDC)
