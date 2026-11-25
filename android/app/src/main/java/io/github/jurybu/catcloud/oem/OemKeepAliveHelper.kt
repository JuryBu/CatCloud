package io.github.jurybu.catcloud.oem

import android.content.ActivityNotFoundException
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings

enum class OemVendor(val displayName: String) {
    REDMAGIC_NUBIA("红魔 / 努比亚"),
    HUAWEI_HONOR("华为 / 荣耀"),
    GENERIC("通用 Android"),
}

/**
 * Two-step OEM background keep-alive helper tailored for RedMagic 8S Pro & Huawei Mate 20.
 * Every intent is guarded by `resolveActivity` and `SecurityException` / `ActivityNotFoundException` fallbacks.
 */
object OemKeepAliveHelper {

    fun detectVendor(): OemVendor {
        val m = Build.MANUFACTURER.orEmpty().lowercase()
        val b = Build.BRAND.orEmpty().lowercase()
        val combined = "$m $b"
        return when {
            combined.contains("nubia") || combined.contains("redmagic") || combined.contains("zte") ->
                OemVendor.REDMAGIC_NUBIA
            combined.contains("huawei") || combined.contains("honor") ->
                OemVendor.HUAWEI_HONOR
            else -> OemVendor.GENERIC
        }
    }

    fun isIgnoringBatteryOptimizations(context: Context): Boolean {
        val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager ?: return false
        return pm.isIgnoringBatteryOptimizations(context.packageName)
    }

    /**
     * Step 1: Request standard Android battery optimization whitelist with safe fallback.
     */
    fun openBatteryWhitelistSettings(context: Context): Boolean {
        val directIntent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
            data = Uri.parse("package:${context.packageName}")
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        if (tryLaunch(context, directIntent)) return true

        val listIntent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        if (tryLaunch(context, listIntent)) return true

        return openAppDetailsSettings(context)
    }

    /**
     * Step 2: Open OEM auto-start / background protection page using 3-tier component fallback.
     */
    fun openOemAutoStartSettings(context: Context): Boolean {
        val candidates: List<ComponentName> = when (detectVendor()) {
            OemVendor.REDMAGIC_NUBIA -> listOf(
                ComponentName("com.zte.heartyservice", "com.zte.heartyservice.setting.ClearAppSettingsActivity"),
                ComponentName("com.nubia.security", "com.nubia.security.app.autoStart.AutoStartActivity"),
                ComponentName("cn.nubia.security2", "cn.nubia.security.app.autoStart.AutoStartActivity"),
                ComponentName("com.zte.heartyservice", "com.zte.heartyservice.autorun.AppAutoRunManager"),
            )
            OemVendor.HUAWEI_HONOR -> listOf(
                ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity"),
                ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.optimize.process.ProtectActivity"),
                ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.appcontrol.activity.StartupAppControlActivity"),
            )
            OemVendor.GENERIC -> emptyList()
        }

        for (comp in candidates) {
            val intent = Intent().apply {
                component = comp
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            if (tryLaunch(context, intent)) return true
        }

        // Package-level launcher fallback for Nubia / Huawei security center
        val fallbackPkgs = when (detectVendor()) {
            OemVendor.REDMAGIC_NUBIA -> listOf("com.zte.heartyservice", "com.nubia.security", "cn.nubia.security2")
            OemVendor.HUAWEI_HONOR -> listOf("com.huawei.systemmanager")
            OemVendor.GENERIC -> emptyList()
        }
        for (pkg in fallbackPkgs) {
            val launch = context.packageManager.getLaunchIntentForPackage(pkg)?.apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            if (launch != null && tryLaunch(context, launch)) return true
        }

        return openAppDetailsSettings(context)
    }

    fun openAppDetailsSettings(context: Context): Boolean {
        val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
            data = Uri.parse("package:${context.packageName}")
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        return tryLaunch(context, intent)
    }

    fun vendorGuidanceText(): String = when (detectVendor()) {
        OemVendor.REDMAGIC_NUBIA ->
            "红魔 / 努比亚机型建议：① 将猫猫云梯设为「不优化」电池；② 在手机管家开启「允许自启动」与「允许后台高耗电」，并在最近任务卡片下滑加锁。"
        OemVendor.HUAWEI_HONOR ->
            "华为 / 荣耀机型建议：① 关闭电池优化；② 在「手机管家 → 应用启动管理」关闭自动管理，手动开启允许自启动、允许关联启动与允许后台活动。"
        OemVendor.GENERIC ->
            "建议将猫猫云梯加入电池「不受限制」名单，并在系统后台管理中允许后台持续运行。"
    }

    private fun tryLaunch(context: Context, intent: Intent): Boolean {
        if (intent.resolveActivity(context.packageManager) == null) return false
        return try {
            context.startActivity(intent)
            true
        } catch (_: SecurityException) {
            false
        } catch (_: ActivityNotFoundException) {
            false
        }
    }
}
