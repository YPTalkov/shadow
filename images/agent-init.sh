#!/bin/busybox sh
export PATH=/sbin:/bin:/usr/sbin:/usr/bin
/bin/busybox mkdir -p /usr/bin /usr/sbin
/bin/busybox --install -s
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /root /tmp /run /etc /work
chmod 700 /root /work
mount -t devpts devpts /dev/pts
echo 'root:x:0:0:root:/root:/bin/sh' > /etc/passwd
ip link set lo up
ulimit -c 0
modprobe virtio_pci
modprobe virtio_mmio
modprobe virtio_console
modprobe virtio_blk
insmod /lib/modules/$(uname -r)/kernel/net/vmw_vsock/vsock.ko
insmod /lib/modules/$(uname -r)/kernel/net/vmw_vsock/vmw_vsock_virtio_transport_common.ko
insmod /lib/modules/$(uname -r)/kernel/net/vmw_vsock/vmw_vsock_virtio_transport.ko
exec >/dev/null 2>&1
cd /
python3 -m guest_transport.agent_runtime
poweroff -f
