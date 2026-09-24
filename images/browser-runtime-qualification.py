"""Synthetic certificate bootstrap, excluded from production browser images."""
import os
from pathlib import Path
import subprocess

from browser_worker.supervisor import ENVIRONMENT, main

nss = Path("/home/pwuser/.local/share/pki/nssdb")
nss.mkdir(parents=True, mode=0o700)
for directory in (nss, nss.parent, nss.parent.parent, nss.parent.parent.parent):
    os.chown(directory, 1001, 1001)
for arguments in (["-N", "--empty-password"], ["-A", "-n", "Shadow synthetic fixture", "-t", "C,,", "-i", "/opt/shadow/fixture-ca.pem"]):
    subprocess.run(["/usr/bin/certutil", "-d", "sql:" + str(nss)] + arguments,
                   env=ENVIRONMENT, user=1001, group=1001, extra_groups=[], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
main()
