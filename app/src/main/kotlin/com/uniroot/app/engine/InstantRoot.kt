package com.uniroot.app.engine

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.FileProvider
import java.io.File

/**
 * "Instant root" (DFReroot second stage) — https://github.com/polygraphene/DFReroot
 *
 * The exploit root is memory-only and dies at every reboot. DFReroot makes it
 * persistent in three steps, all scripted here (no GUI of the helper apps is
 * ever shown):
 *
 *  1. INJECT (needs the exploit root, once): run DFInstaller's root
 *     `app_process` entry (InjectMain) to insert the DFReroot signing key into
 *     the `android.uid.system` shared-user `pastSigs` of /data/system/packages.xml.
 *  2. SOFT REBOOT: `kill $(pidof system_server)` — PMS re-reads packages.xml.
 *     The KernelSU late-load module lives in kernel memory and SURVIVES this.
 *  3. INSTALL (AutoRootService finish step, after the soft reboot, su still up):
 *     `pm install` df_reroot.apk → DFReroot installs as android.uid.system and
 *     stays across reboots. Its own BOOT_COMPLETED receiver then re-roots the
 *     phone (Dirty Frag → LKM permissive → ksud late-load) with no exploit.
 *
 * Both helper APKs are bundled in assets/df/. DFInstaller is only used as the
 * CLASSPATH dex container for InjectMain — it never needs to be installed.
 */
class InstantRoot(private val context: Context, private val log: (String) -> Unit = {}) {

    companion object {
        const val PKG_INSTALLER = "com.polygraphene.df.installer"
        const val PKG_REROOT = "com.polygraphene.df.reroot"
        private const val ASSET_INSTALLER = "df/df_installer.apk"
        private const val ASSET_REROOT = "df/df_reroot.apk"
        private const val TMP_INSTALLER = "/data/local/tmp/df_installer.apk"
        private const val TMP_REROOT = "/data/local/tmp/df_reroot.apk"
        const val LOG_FILE = "instant-root.log"
        const val ACTION_INSTALL_STATUS = "com.uniroot.app.INSTALL_STATUS"
    }

    /** Every InstantRoot line lands in filesDir/instant-root.log (Instant Root log viewer). */
    fun record(line: String) {
        log(line)
        runCatching {
            File(context.filesDir, LOG_FILE).appendText(line.trimEnd() + "\n")
        }
    }

    fun readLog(): String =
        runCatching { File(context.filesDir, LOG_FILE).readText() }.getOrDefault("")

    // ------------------------------------------------------------------
    // State queries
    // ------------------------------------------------------------------

    fun assetsAvailable(): Boolean =
        runCatching { context.assets.open(ASSET_REROOT).use { it.read() != -1 } }.getOrDefault(false) &&
            runCatching { context.assets.open(ASSET_INSTALLER).use { it.read() != -1 } }.getOrDefault(false)

    fun isHelperInstalled(): Boolean = runCatching {
        context.packageManager.getPackageInfo(PKG_REROOT, 0)
        true
    }.getOrDefault(false)

    // ------------------------------------------------------------------
    // Root plumbing — two channels, first available wins:
    //   1. exploit root socket (Local profiles): the su daemon spawned by the
    //      last exploit lives until reboot; helper -c = instant root, no popup
    //   2. app su: may pop the grant dialog
    // ------------------------------------------------------------------

    fun su(script: String, timeoutSec: Long = 90, quiet: Boolean = false): Pair<Int, String>? {
        // App su — validated on-device. The grant persists on disk; without it
        // (or without a loaded KernelSU), exec("su") fails instantly. Probes
        // (suId polling) stay quiet so the log is not flooded at boot.
        if (!quiet) record("[InstantRoot] root channel: app su")
        return try {
            val p = ProcessBuilder("su", "-c", script).redirectErrorStream(true).start()
            val out = StringBuilder()
            val reader = Thread {
                runCatching { p.inputStream.bufferedReader().forEachLine { synchronized(out) { out.appendLine(it) } } }
            }.apply { isDaemon = true; start() }
            val finished = p.waitFor(timeoutSec, java.util.concurrent.TimeUnit.SECONDS)
            if (!finished) { p.destroyForcibly(); if (!quiet) record("[InstantRoot] app su timeout"); return null }
            reader.join(2_000)
            val rc = p.exitValue()
            if (!quiet || rc == 0) record("[InstantRoot] app su rc=$rc out=${out.take(120)}")
            rc to out.toString()
        } catch (e: Exception) {
            if (!quiet) record("[InstantRoot] app su failed: ${e.javaClass.simpleName}: ${e.message}")
            null
        }
    }

    /** null when su is not granted yet (KernelSU popup pending/denied). */
    fun suId(timeoutSec: Long = 90): String? {
        // Plain "su" goes through the KernelSU/Next execve hook; the real binary
        // under /data/adb/ksu/bin is the fallback for hook-less setups.
        for (cmd in listOf("id", "/data/adb/ksu/bin/su -c id")) {
            val (rc, out) = su(cmd, timeoutSec = timeoutSec, quiet = true) ?: continue
            if (rc == 0 && out.contains("uid=0")) return out
        }
        return null
    }

    /**
     * Grant-independent root signals for the boot watcher: the kernelsu
     * module in /proc/modules (readable when SELinux allows it) and the
     * /dev/dfm3 marker the DF chain leaves once ksud was bind-mounted and
     * exec'd. Best-effort — suId() stays the authoritative check.
     */
    fun rootSignals(): Boolean {
        val modules = runCatching {
            java.io.File("/proc/modules").readText().contains("kernelsu", ignoreCase = true)
        }.getOrDefault(false)
        if (modules) return true
        return runCatching { java.io.File("/dev/dfm3").exists() }.getOrDefault(false)
    }

    // ------------------------------------------------------------------
    // Steps
    // ------------------------------------------------------------------

    /** Copies the two bundled helper APKs to /data/local/tmp (readable by root). */
    fun stageApks(): Boolean {
        if (!assetsAvailable()) { log("[InstantRoot] df/*.apk assets missing — rebuild the app"); return false }
        return runCatching {
            val ext = context.getExternalFilesDir(null) ?: return false
            for (asset in listOf(ASSET_INSTALLER, ASSET_REROOT)) {
                val dest = File(ext, asset.substringAfterLast('/'))
                context.assets.open(asset).use { i -> dest.outputStream().use { o -> i.copyTo(o) } }
            }
            val rc = su("cp ${File(ext, "df_installer.apk").absolutePath} $TMP_INSTALLER" +
                " && cp ${File(ext, "df_reroot.apk").absolutePath} $TMP_REROOT" +
                " && chmod 644 $TMP_INSTALLER $TMP_REROOT", timeoutSec = 30)?.first
            if (rc != 0) { log("[InstantRoot] could not stage APKs to /data/local/tmp"); return false }
            record("[InstantRoot] Helper APKs staged")
            true
        }.getOrDefault(false)
    }

    /**
     * Signing-cert hex of the bundled df_reroot.apk, computed in-app
     * (same as DFInstaller's SigKey: PackageManager on the archive). This
     * lets InjectMain run with the light --keyhex path instead of the heavy
     * --apk path (which builds the whole System Context and can hang).
     */
    fun rerootKeyHex(): String? {
        return runCatching {
            val ext = context.getExternalFilesDir(null) ?: return null
            val apk = File(ext, "df_reroot.apk")
            if (!apk.exists() || apk.length() == 0L) {
                context.assets.open(ASSET_REROOT).use { i -> apk.outputStream().use { o -> i.copyTo(o) } }
            }
            val pi = context.packageManager.getPackageArchiveInfo(
                apk.absolutePath, android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES
            ) ?: return null
            val cert = pi.signingInfo?.apkContentsSigners?.firstOrNull() ?: return null
            cert.toByteArray().joinToString("") { "%02x".format(it) }
        }.getOrNull()
    }

    private fun runAppProcess(hex: String, args: String): String? {
        val script = "CLASSPATH=$TMP_INSTALLER app_process /system/bin --nice-name=df_inject " +
            "com.polygraphene.df.installer.InjectMain --keyhex $hex $args"
        return su(script, timeoutSec = 120)?.let { (rc, out) -> out + if (rc == 0) "" else "\n[rc=$rc]" }
    }

    /** True when packages.xml already carries the key (all targets injected). */
    fun checkInjected(hex: String): Boolean {
        val out = runAppProcess(hex, "--check") ?: return false
        record("[InstantRoot] check:\n${out.trim()}")
        return out.contains("all_injected=true")
    }

    /** Step 1 — inject the signing key into packages.xml (light --keyhex path). */
    fun inject(): Boolean {
        val hex = rerootKeyHex() ?: run {
            record("[InstantRoot] inject failed: cannot read df_reroot.apk cert")
            return false
        }
        if (checkInjected(hex)) { record("[InstantRoot] Key already injected"); return true }
        val out = runAppProcess(hex, "--targets android.uid.system") ?: run {
            record("[InstantRoot] inject failed: no root")
            return false
        }
        record("[InstantRoot] inject:\n${out.trim()}")
        return out.contains("[+] DONE") && !out.contains("[x] FAILED")
    }

    /** Revert step 1 (removes only our key). */
    fun removeKey(): Boolean {
        val hex = rerootKeyHex() ?: return false
        val out = runAppProcess(hex, "--uninstall") ?: return false
        record("[InstantRoot] uninstall-key:\n${out.trim()}")
        return out.contains("[+] DONE") || out.contains("nothing to write")
    }

    /** Step 2 — restart the framework; the exploit root survives it. */
    fun softReboot(): Boolean = su("kill \$(pidof system_server)", timeoutSec = 20)?.first?.let { it == 0 } ?: false

    /**
     * Step 3 — MANUAL helper install: fires Android's own install dialog for
     * df_reroot.apk. The user confirms ("Install"), PMS checks the injected
     * key in packages.xml and the helper lands as android.uid.system. No root
     * needed for this step — UniRoot never installs it silently.
     * Returns null when the APK cannot be staged.
     */
    fun helperInstallIntent(): Intent? {
        val apk = runCatching {
            val ext = context.getExternalFilesDir(null) ?: return null
            val dest = File(ext, "df_reroot.apk")
            if (!dest.exists() || dest.length() == 0L) {
                context.assets.open(ASSET_REROOT).use { i -> dest.outputStream().use { o -> i.copyTo(o) } }
            }
            dest
        }.getOrNull() ?: return null
        val uri: Uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", apk)
        record("[InstantRoot] install prompt for ${apk.absolutePath} (${apk.length()} bytes)")
        return Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        }
    }

    /**
     * Stage THE PROFILE'S OWN ksud as the boot re-root payload — wrapper
     * design, works with ANY ksud (KernelSU, Next, future profiles):
     *
     *   /data/local/tmp/ksud-classic|ksud-next  the profile's real ksud
     *     (persistent, readable by the DF chain's modprobe context)
     *   /data/local/tmp/dfreroot-flavor         "ksu" | "next"
     *   /data/system/dfreroot-ksud              the wrapper script (755):
     *     at boot it copies the flavor's ksud to .ksud-stage, bind-mounts it
     *     over /system/bin/atrace (real file — no toybox clobber, DEFEX
     *     bypass) and execs it with a plain `late-load`, i.e. exactly the
     *     invocation every ksud supports.
     *
     * Needs live root (exploit socket or su).
     */
    fun stageProfileKsud(ksudPath: String, flavor: String): Boolean {
        if (ksudPath.isBlank()) return false
        val flavorTag = if (flavor == "kernelsu_next") "next" else "ksu"
        val persistentName = if (flavor == "kernelsu_next") "ksud-next" else "ksud-classic"
        val wrapperAsset = runCatching {
            context.assets.open("df/dfreroot-wrapper.sh").use { it.readBytes() }
        }.getOrNull() ?: run {
            record("[InstantRoot] df/dfreroot-wrapper.sh asset missing — rebuild the app")
            return false
        }
        val tmpWrapper = File(context.getExternalFilesDir(null), "dfreroot-wrapper.sh")
        runCatching { tmpWrapper.writeBytes(wrapperAsset) }
        val (rc, out) = su(
            "/system/bin/cp '$ksudPath' /data/local/tmp/$persistentName" +
                " && /system/bin/chmod 755 /data/local/tmp/$persistentName" +
                " && echo '$flavorTag' > /data/local/tmp/dfreroot-flavor" +
                " && /system/bin/cp '${tmpWrapper.absolutePath}' /data/system/dfreroot-ksud" +
                " && /system/bin/chown root:root /data/system/dfreroot-ksud" +
                " && /system/bin/chmod 755 /data/system/dfreroot-ksud" +
                " && echo KSUD_STAGED",
            timeoutSec = 60,
        ) ?: return false
        record("[InstantRoot] stage profile ksud rc=$rc out=${out.take(160)}")
        return rc == 0 && out.contains("KSUD_STAGED")
    }

    /**
     * THE stopped-state trap: a freshly installed (or updated) package does
     * not receive LOCKED/BOOT_COMPLETED until unstopped. `pm unstop` via su
     * is the reliable way; the helper MainActivity launch is the fallback.
     */
    fun unstopHelper(): Boolean {
        val (rc, out) = su("pm unstop $PKG_REROOT", timeoutSec = 30) ?: return false
        record("[InstantRoot] pm unstop rc=$rc out=${out.take(80)}")
        return rc == 0 || out.contains("already", ignoreCase = true)
    }

    /**
     * Fire the NATIVE Android install dialog for the bundled df_reroot.apk
     * via PackageInstaller — the system shows its own confirmation popup,
     * no UniRoot activity needed. Returns a human log line; the caller
     * registers a receiver for ACTION_INSTALL_STATUS to handle the result
     * (STATUS_PENDING_USER_ACTION -> start the confirm activity).
     */
    fun helperInstallSession(): String {
        val apk = runCatching {
            val ext = context.getExternalFilesDir(null) ?: error("no external dir")
            val dest = File(ext, "df_reroot.apk")
            if (!dest.exists() || dest.length() == 0L) {
                context.assets.open(ASSET_REROOT).use { i -> dest.outputStream().use { o -> i.copyTo(o) } }
            }
            dest
        }.getOrElse { return "apk stage failed: $it" }
        return runCatching {
            val pi = context.packageManager.packageInstaller
            val params = android.content.pm.PackageInstaller.SessionParams(
                android.content.pm.PackageInstaller.SessionParams.MODE_FULL_INSTALL
            )
            val sessionId = pi.createSession(params)
            val session = pi.openSession(sessionId)
            session.openWrite("df_reroot.apk", 0, apk.length()).use { out ->
                apk.inputStream().use { it.copyTo(out) }
                session.fsync(out)
            }
            val statusIntent = Intent(ACTION_INSTALL_STATUS).setPackage(context.packageName)
            val sender = android.app.PendingIntent.getBroadcast(
                context, sessionId, statusIntent,
                android.app.PendingIntent.FLAG_MUTABLE or android.app.PendingIntent.FLAG_UPDATE_CURRENT,
            )
            session.commit(sender.intentSender)
            session.close()
            "install session $sessionId committed"
        }.getOrElse { "install session failed: $it" }
    }

    /**
     * Notifications are the only channel the user can SEE at boot (toasts from
     * a boot-started service are suppressed). POST_NOTIFICATIONS is a runtime
     * permission on Android 13+ — when denied, every notification (including
     * the FGS one) is silently dropped. With live root we grant it to
     * ourselves: `pm grant` persists across reboots.
     */
    fun ensureNotificationPermission(): String {
        val nm = context.getSystemService(android.app.NotificationManager::class.java)
        if (nm?.areNotificationsEnabled() == true) return "notifications already enabled"
        val (rc, out) = su(
            "pm grant ${context.packageName} android.permission.POST_NOTIFICATIONS",
            timeoutSec = 20,
        ) ?: return "no root — cannot grant notifications"
        runCatching { Thread.sleep(500) }
        return "pm grant rc=$rc enabled=${nm?.areNotificationsEnabled()} out=${out.take(60)}"
    }

    /** Enable/disable the boot re-root without uninstalling (root required). */
    fun setHelperEnabled(enable: Boolean): Boolean {
        val action = if (enable) "enable" else "disable-user"
        val (rc, out) = su("pm $action $PKG_REROOT", timeoutSec = 30) ?: return false
        return rc == 0 || out.contains("already")
    }

    /**
     * Full removal: helper packages first (concrete, observable), then the
     * packages.xml key. Treats "not installed" as success and logs everything.
     */
    fun uninstallAll(): Boolean {
        var helperGone = !isHelperInstalled()
        for (pkg in listOf(PKG_REROOT, PKG_INSTALLER)) {
            val res = su("pm uninstall $pkg", timeoutSec = 60)
            if (res == null) { record("[InstantRoot] pm uninstall $pkg: no root"); continue }
            val (rc, out) = res
            record("[InstantRoot] pm uninstall $pkg rc=$rc out=${out.take(100)}")
            if (pkg == PKG_REROOT && (rc == 0 || out.contains("not installed", ignoreCase = true))) helperGone = true
        }
        removeKey()
        runCatching {
            File("/data/system/dfreroot-boot.log").delete()
            File("/data/system/dfreroot-attempts").delete()
        }
        return helperGone
    }
}
