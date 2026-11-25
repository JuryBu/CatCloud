package io.github.jurybu.catcloud.ui

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.path
import androidx.compose.ui.unit.dp

/**
 * Ultra-lightweight custom vector icon set replacing `material-icons-extended` (saves ~12 MiB).
 */
object CatIcons {

    private fun icon(name: String, block: ImageVector.Builder.() -> Unit): ImageVector =
        ImageVector.Builder(
            name = name,
            defaultWidth = 24.dp,
            defaultHeight = 24.dp,
            viewportWidth = 24f,
            viewportHeight = 24f,
        ).apply(block).build()

    private val stroke = SolidColor(Color.Black)

    val Home: ImageVector by lazy {
        icon("Home") {
            path(stroke = stroke, strokeLineWidth = 2f, strokeLineCap = StrokeCap.Round, strokeLineJoin = StrokeJoin.Round) {
                moveTo(3f, 10.5f)
                lineTo(12f, 3.5f)
                lineTo(21f, 10.5f)
                moveTo(5.5f, 9f)
                verticalLineTo(20f)
                horizontalLineTo(18.5f)
                verticalLineTo(9f)
            }
        }
    }

    val Nodes: ImageVector by lazy {
        icon("Nodes") {
            path(stroke = stroke, strokeLineWidth = 2f, strokeLineCap = StrokeCap.Round, strokeLineJoin = StrokeJoin.Round) {
                moveTo(4f, 6f); horizontalLineTo(20f)
                moveTo(4f, 12f); horizontalLineTo(20f)
                moveTo(4f, 18f); horizontalLineTo(14f)
            }
        }
    }

    val Settings: ImageVector by lazy {
        icon("Settings") {
            path(stroke = stroke, strokeLineWidth = 2f, strokeLineCap = StrokeCap.Round, strokeLineJoin = StrokeJoin.Round) {
                moveTo(12f, 8.5f)
                arcTo(3.5f, 3.5f, 0f, true, true, 11.99f, 8.5f)
                moveTo(12f, 3f); verticalLineTo(5f)
                moveTo(12f, 19f); verticalLineTo(21f)
                moveTo(3f, 12f); horizontalLineTo(5f)
                moveTo(19f, 12f); horizontalLineTo(21f)
                moveTo(5.6f, 5.6f); lineTo(7.1f, 7.1f)
                moveTo(16.9f, 16.9f); lineTo(18.4f, 18.4f)
                moveTo(18.4f, 5.6f); lineTo(16.9f, 7.1f)
                moveTo(7.1f, 16.9f); lineTo(5.6f, 18.4f)
            }
        }
    }

    val QrScan: ImageVector by lazy {
        icon("QrScan") {
            path(stroke = stroke, strokeLineWidth = 2f, strokeLineCap = StrokeCap.Round, strokeLineJoin = StrokeJoin.Round) {
                moveTo(4f, 8f); verticalLineTo(4f); horizontalLineTo(8f)
                moveTo(16f, 4f); horizontalLineTo(20f); verticalLineTo(8f)
                moveTo(20f, 16f); verticalLineTo(20f); horizontalLineTo(16f)
                moveTo(8f, 20f); horizontalLineTo(4f); verticalLineTo(16f)
                moveTo(7f, 12f); horizontalLineTo(17f)
            }
        }
    }

    val Power: ImageVector by lazy {
        icon("Power") {
            path(stroke = stroke, strokeLineWidth = 2.4f, strokeLineCap = StrokeCap.Round) {
                moveTo(12f, 3f); verticalLineTo(11f)
                moveTo(6.8f, 6.8f)
                arcTo(7.5f, 7.5f, 0f, true, false, 17.2f, 6.8f)
            }
        }
    }

    val Bolt: ImageVector by lazy {
        icon("Bolt") {
            path(stroke = stroke, strokeLineWidth = 2f, strokeLineCap = StrokeCap.Round, strokeLineJoin = StrokeJoin.Round) {
                moveTo(13f, 2.5f)
                lineTo(5.5f, 13f)
                horizontalLineTo(11.5f)
                lineTo(10.5f, 21.5f)
                lineTo(18.5f, 11f)
                horizontalLineTo(12.5f)
                close()
            }
        }
    }

    val Speed: ImageVector by lazy {
        icon("Speed") {
            path(stroke = stroke, strokeLineWidth = 2f, strokeLineCap = StrokeCap.Round, strokeLineJoin = StrokeJoin.Round) {
                moveTo(4f, 17f)
                arcTo(8.5f, 8.5f, 0f, true, true, 20f, 17f)
                moveTo(12f, 14f); lineTo(16.5f, 9.5f)
            }
        }
    }

    val Add: ImageVector by lazy {
        icon("Add") {
            path(stroke = stroke, strokeLineWidth = 2.2f, strokeLineCap = StrokeCap.Round) {
                moveTo(12f, 5f); verticalLineTo(19f)
                moveTo(5f, 12f); horizontalLineTo(19f)
            }
        }
    }

    val ChevronRight: ImageVector by lazy {
        icon("ChevronRight") {
            path(stroke = stroke, strokeLineWidth = 2f, strokeLineCap = StrokeCap.Round, strokeLineJoin = StrokeJoin.Round) {
                moveTo(9f, 6f); lineTo(15f, 12f); lineTo(9f, 18f)
            }
        }
    }

    val Close: ImageVector by lazy {
        icon("Close") {
            path(stroke = stroke, strokeLineWidth = 2.2f, strokeLineCap = StrokeCap.Round) {
                moveTo(6f, 6f); lineTo(18f, 18f)
                moveTo(18f, 6f); lineTo(6f, 18f)
            }
        }
    }

    val Check: ImageVector by lazy {
        icon("Check") {
            path(stroke = stroke, strokeLineWidth = 2.2f, strokeLineCap = StrokeCap.Round, strokeLineJoin = StrokeJoin.Round) {
                moveTo(5f, 12.5f); lineTo(9.5f, 17f); lineTo(19f, 7.5f)
            }
        }
    }

    val Refresh: ImageVector by lazy {
        icon("Refresh") {
            path(stroke = stroke, strokeLineWidth = 2f, strokeLineCap = StrokeCap.Round, strokeLineJoin = StrokeJoin.Round) {
                moveTo(19.5f, 11f)
                arcTo(7.5f, 7.5f, 0f, true, false, 17.5f, 17.2f)
                moveTo(19.5f, 6f); verticalLineTo(11f); horizontalLineTo(14.5f)
            }
        }
    }

    val Copy: ImageVector by lazy {
        icon("Copy") {
            path(stroke = stroke, strokeLineWidth = 2f, strokeLineCap = StrokeCap.Round, strokeLineJoin = StrokeJoin.Round) {
                moveTo(9f, 9f); horizontalLineTo(19f); verticalLineTo(19f); horizontalLineTo(9f); close()
                moveTo(15f, 9f); verticalLineTo(5f); horizontalLineTo(5f); verticalLineTo(15f); horizontalLineTo(9f)
            }
        }
    }

    val Delete: ImageVector by lazy {
        icon("Delete") {
            path(stroke = stroke, strokeLineWidth = 2f, strokeLineCap = StrokeCap.Round, strokeLineJoin = StrokeJoin.Round) {
                moveTo(4f, 7f); horizontalLineTo(20f)
                moveTo(9f, 7f); verticalLineTo(4f); horizontalLineTo(15f); verticalLineTo(7f)
                moveTo(7f, 7f); verticalLineTo(20f); horizontalLineTo(17f); verticalLineTo(7f)
            }
        }
    }

    val Shield: ImageVector by lazy {
        icon("Shield") {
            path(stroke = stroke, strokeLineWidth = 2f, strokeLineCap = StrokeCap.Round, strokeLineJoin = StrokeJoin.Round) {
                moveTo(12f, 3f)
                lineTo(19f, 6f)
                verticalLineTo(12f)
                curveTo(19f, 16.5f, 15.8f, 19.6f, 12f, 21f)
                curveTo(8.2f, 19.6f, 5f, 16.5f, 5f, 12f)
                verticalLineTo(6f)
                close()
            }
        }
    }
}
