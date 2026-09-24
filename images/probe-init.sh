#!/bin/busybox sh
export PATH=/sbin:/bin:/usr/sbin:/usr/bin
/bin/busybox mkdir -p /usr/bin /usr/sbin
/bin/busybox --install -s
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /root /tmp /run /etc
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
exec >/dev/hvc0 2>&1
echo SHADOW_PROBE_BEGIN
echo UID=$(id -u)
echo NETWORK_DEVICES=$(ls /sys/class/net)
echo VIRTIO_DEVICES=$(ls /sys/bus/virtio/devices | tr '\n' ',')
echo SWAP_DEVICES=$(awk 'END {print NR-1}' /proc/swaps)
echo HOST_HOME_PRESENT=$(test -e /Users && echo yes || echo no)
echo SHARED_MOUNTS=$(awk '$3 == "virtiofs" || $3 == "9p" {n++} END {print n+0}' /proc/mounts)
echo IP_ROUTE_COUNT=$(awk 'NR > 1 {n++} END {print n+0}' /proc/net/route)
python3 /probe-boundary.py
case "$(cat /proc/cmdline)" in
  *shadow.role=agent*) python3 /probe-agent-api.py; python3 /probe-codex.py ;;
esac
case "$(cat /proc/cmdline)" in
  *shadow.role=browser*shadow.egress=1*) python3 /probe-egress.py ;;
esac
echo SHADOW_PROBE_END
sync
poweroff -f
