package io.github.jurybu.catcloud.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import io.github.jurybu.catcloud.data.ThemePreference

@Immutable
data class CatCloudPalette(
    val isDark: Boolean,
    val background: Color,
    val surface: Color,
    val surfaceElevated: Color,
    val border: Color,
    val textPrimary: Color,
    val textSecondary: Color,
    val accentStarBlue: Color,
    val mintSingle: Color,
    val mintSingleBg: Color,
    val warmGoldGroup: Color,
    val warmGoldGroupBg: Color,
    val latencyGood: Color,
    val latencyWarn: Color,
    val danger: Color,
)

private val MidnightBluePalette = CatCloudPalette(
    isDark = true,
    background = Color(0xFF0B1220),
    surface = Color(0xFF131D31),
    surfaceElevated = Color(0xFF1A2742),
    border = Color(0xFF263859),
    textPrimary = Color(0xFFEAF1FF),
    textSecondary = Color(0xFF93A7C9),
    accentStarBlue = Color(0xFF4F8BFF),
    mintSingle = Color(0xFF4CE0B3),
    mintSingleBg = Color(0xFF102C2B),
    warmGoldGroup = Color(0xFFF5B856),
    warmGoldGroupBg = Color(0xFF2D2516),
    latencyGood = Color(0xFF3DDC97),
    latencyWarn = Color(0xFFF5B856),
    danger = Color(0xFFFF6B7A),
)

private val DawnLightPalette = CatCloudPalette(
    isDark = false,
    background = Color(0xFFF4F7FC),
    surface = Color(0xFFFFFFFF),
    surfaceElevated = Color(0xFFEBF1FA),
    border = Color(0xFFD5E0F0),
    textPrimary = Color(0xFF111B2E),
    textSecondary = Color(0xFF5A6B88),
    accentStarBlue = Color(0xFF2563EB),
    mintSingle = Color(0xFF0D946F),
    mintSingleBg = Color(0xFFE6F7F1),
    warmGoldGroup = Color(0xFFC47B14),
    warmGoldGroupBg = Color(0xFFFFF4E0),
    latencyGood = Color(0xFF0D946F),
    latencyWarn = Color(0xFFD97706),
    danger = Color(0xFFDC2626),
)

val LocalCatPalette = staticCompositionLocalOf { MidnightBluePalette }

@Composable
fun CatCloudTheme(
    preference: ThemePreference,
    content: @Composable () -> Unit,
) {
    val useDark = when (preference) {
        ThemePreference.MIDNIGHT_BLUE -> true
        ThemePreference.DAWN_LIGHT -> false
        ThemePreference.SYSTEM -> isSystemInDarkTheme()
    }
    val palette = if (useDark) MidnightBluePalette else DawnLightPalette

    val colorScheme = if (useDark) {
        darkColorScheme(
            primary = palette.accentStarBlue,
            onPrimary = Color.White,
            secondary = palette.mintSingle,
            tertiary = palette.warmGoldGroup,
            background = palette.background,
            surface = palette.surface,
            surfaceVariant = palette.surfaceElevated,
            onBackground = palette.textPrimary,
            onSurface = palette.textPrimary,
            onSurfaceVariant = palette.textSecondary,
            outline = palette.border,
            error = palette.danger,
        )
    } else {
        lightColorScheme(
            primary = palette.accentStarBlue,
            onPrimary = Color.White,
            secondary = palette.mintSingle,
            tertiary = palette.warmGoldGroup,
            background = palette.background,
            surface = palette.surface,
            surfaceVariant = palette.surfaceElevated,
            onBackground = palette.textPrimary,
            onSurface = palette.textPrimary,
            onSurfaceVariant = palette.textSecondary,
            outline = palette.border,
            error = palette.danger,
        )
    }

    CompositionLocalProvider(LocalCatPalette provides palette) {
        MaterialTheme(
            colorScheme = colorScheme,
            content = content,
        )
    }
}
