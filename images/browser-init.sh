#!/bin/busybox sh
export PATH=/sbin:/bin:/usr/sbin:/usr/bin
/bin/busybox mkdir -p /usr/bin /usr/sbin
/bin/busybox --install -s
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /dev/shm /tmp /run /newroot
mount -t devpts devpts /dev/pts
mount -t tmpfs -o size=512m,mode=1777 tmpfs /dev/shm
ip link set lo up
ulimit -c 0
echo '|/bin/false' > /proc/sys/kernel/core_pattern
modprobe virtio_pci
modprobe virtio_mmio
modprobe virtio_console
modprobe virtio_blk
modprobe vmw_vsock_virtio_transport
modprobe squashfs
modprobe virtio_gpu
modprobe virtio_input
modprobe evdev
modprobe xhci_pci
modprobe usbhid
modprobe hid_generic
exec >/dev/hvc0 2>&1
echo SHADOW_BROWSER_BEGIN
mount -t squashfs -o ro /dev/vda /newroot || poweroff -f
mkdir -p /payload
mount -t tmpfs -o size=16m,mode=755 tmpfs /payload
cp -a /shadow/. /payload/
mount --move /payload /newroot/opt/shadow
mount -o remount,ro /newroot/opt/shadow
for directory in proc sys dev; do mount --move /$directory /newroot/$directory; done
mount -t tmpfs -o size=1g,mode=1777 tmpfs /newroot/tmp
mount -t tmpfs -o size=32m,mode=755 tmpfs /newroot/run
mount -t tmpfs -o size=128m,mode=1777 tmpfs /newroot/var/tmp
mount -t tmpfs -o size=128m,mode=700 tmpfs /newroot/home/pwuser
chown 1001:1001 /newroot/home/pwuser
export PYTHONPATH=/opt/shadow:/opt/shadow-deps
export PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
export PYTHONDONTWRITEBYTECODE=1
exec switch_root -c /dev/hvc0 /newroot /usr/bin/python3 /opt/shadow/boot_probe.py
