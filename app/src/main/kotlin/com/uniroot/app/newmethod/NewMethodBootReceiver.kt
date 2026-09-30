package com.uniroot.app.newmethod

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Boot auto-root for the NEW method — the receiver does ONE thing: start
 * [DfBootService] (foreground = the process survives the boot memory
 * pressure, the same pattern as the OLD method's AutoRootService). All the
 * orchestration lives in the service. The ENGINE IS UNTOUCHED.
 *
 * The old auto-root (profiles / ghostlock, AutoRoot.kt) is untouched.
 */
class NewMethodBootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        if (action != Intent.ACTION_LOCKED_BOOT_COMPLETED && action != Intent.ACTION_BOOT_COMPLETED) return
        if (java.io.File("/dev/df").exists()) return
        DfBootService.start(context)
    }

    companion object {
        const val PREFS = "uniroot_newmethod"
        const val PREF_NEXT = "flavor_next"
        const val PREF_AUTO_SOFT_REBOOT = "auto_soft_reboot"
    }
}
