package io.github.jurybu.catcloud.oem

import android.app.Activity
import android.os.Build
import android.view.Display

/**
 * Unlocks native high refresh rate (e.g. 120Hz on RedMagic 8S Pro) by selecting the highest
 * `refreshRate` among same-resolution `display.supportedModes`.
 * On 60Hz devices (e.g. Huawei Mate 20), performs a safe no-op.
 */
object RefreshRateHelper {

    fun unlockHighRefreshRate(activity: Activity): Float {
        val display: Display = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            activity.display ?: return 60f
        } else {
            @Suppress("DEPRECATION")
            activity.windowManager.defaultDisplay ?: return 60f
        }

        val currentMode = display.mode
        val supported = display.supportedModes ?: return currentMode.refreshRate
        val bestSameResolution = supported
            .filter {
                it.physicalWidth == currentMode.physicalWidth &&
                    it.physicalHeight == currentMode.physicalHeight
            }
            .maxByOrNull { it.refreshRate }
            ?: return currentMode.refreshRate

        if (bestSameResolution.refreshRate > currentMode.refreshRate + 1f &&
            bestSameResolution.modeId != currentMode.modeId
        ) {
            val lp = activity.window.attributes
            if (lp.preferredDisplayModeId != bestSameResolution.modeId) {
                lp.preferredDisplayModeId = bestSameResolution.modeId
                activity.window.attributes = lp
            }
        }
        return bestSameResolution.refreshRate
    }
}
