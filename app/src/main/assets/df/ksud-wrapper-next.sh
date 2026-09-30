#!/system/bin/sh
# NEW METHOD (fast) — KernelSU Next wrapper, exec'd by the DirtyFrag chain as
# "logcat" (root, vendor_modprobe ctx). The S938X Next ksud requires
# /data/local/tmp/.ksud-stage (hardcoded staging source, rename to /data/adb)
# which nothing creates in the DF chain — this wrapper prepares it from the
# app's persistent copy, bind-mounts the stage over /system/bin/atrace (REAL
# file, never a toybox symlink) and execs a plain `late-load`.
# Absolute paths only: no usable PATH in the modprobe context.
REAL=/data/data/com.example.universalsystemporter/ksud-next-real
[ -f "$REAL" ] || exit 1
/system/bin/cp -f "$REAL" /data/local/tmp/.ksud-stage || exit 1
/system/bin/chmod 755 /data/local/tmp/.ksud-stage || exit 1
/system/bin/mount -o bind /data/local/tmp/.ksud-stage /system/bin/atrace || exit 1
/system/bin/atrace late-load &
exit 0
