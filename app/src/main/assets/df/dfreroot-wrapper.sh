#!/system/bin/sh
# DFReroot flavor wrapper (absolute paths: modprobe has no usable PATH).
# Exec'd by the DF chain as "logcat"; ignores the incoming argv (the staged
# ksud may not support --stage-from) and re-execs the profile's real ksud
# bind-mounted over /system/bin/atrace (real file -> no toybox clobber,
# DEFEX bypass).
F=$(/system/bin/cat /data/local/tmp/dfreroot-flavor 2>/dev/null)
REAL=/data/local/tmp/ksud-classic
[ "$F" = "next" ] && REAL=/data/local/tmp/ksud-next
[ -f "$REAL" ] || REAL=/data/local/tmp/ksud-classic
/system/bin/cp -f "$REAL" /data/local/tmp/.ksud-stage || exit 1
/system/bin/chmod 755 /data/local/tmp/.ksud-stage
/system/bin/mount -o bind /data/local/tmp/.ksud-stage /system/bin/atrace || exit 1
exec /system/bin/atrace late-load
