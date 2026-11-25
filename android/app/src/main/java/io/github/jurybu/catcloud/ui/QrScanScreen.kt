package io.github.jurybu.catcloud.ui

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Matrix
import android.graphics.SurfaceTexture
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraManager
import android.net.Uri
import android.util.Size
import android.view.Surface
import android.view.TextureView
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.LifecycleOwner
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Zero-`camera-view` lightweight QR scanner built directly on `CameraX camera-core/camera2/lifecycle`,
 * native [TextureView], and offline `com.google.zxing:core:3.5.4`.
 * Zero disk writes; deterministically unbinds camera & shuts down executor in [DisposableEffect].
 */
@Composable
fun QrScanScreen(
    onResult: (String) -> Unit,
    onClose: () -> Unit,
) {
    val context = LocalContext.current
    val lifecycleOwner = context as? LifecycleOwner
    var hasCameraPerm by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED
        )
    }
    var scanError by remember { mutableStateOf<String?>(null) }
    val delivered = remember { AtomicBoolean(false) }
    val analysisExecutor = remember { Executors.newSingleThreadExecutor() }
    var boundProvider by remember { mutableStateOf<ProcessCameraProvider?>(null) }
    var activeSurface by remember { mutableStateOf<Surface?>(null) }

    val permLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        hasCameraPerm = granted
        if (!granted) scanError = "未获得相机权限，仍可从相册选图识别二维码"
    }

    val galleryLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        val decoded = runCatching { decodeGalleryImage(context, uri) }.getOrNull()
        if (!decoded.isNullOrBlank()) {
            if (delivered.compareAndSet(false, true)) {
                onResult(decoded)
            }
        } else {
            scanError = "图片中未识别到有效二维码，请换一张清晰截图"
        }
    }

    LaunchedEffect(Unit) {
        if (!hasCameraPerm) {
            permLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    DisposableEffect(Unit) {
        onDispose {
            runCatching { boundProvider?.unbindAll() }
            runCatching { activeSurface?.release() }
            activeSurface = null
            analysisExecutor.shutdownNow()
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.Black)
            .safeDrawingPadding()
    ) {
        if (hasCameraPerm && lifecycleOwner != null) {
            val zxingReader = remember {
                MultiFormatReader().apply {
                    setHints(
                        mapOf(
                            DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
                            DecodeHintType.CHARACTER_SET to "UTF-8",
                        )
                    )
                }
            }
            AndroidView(
                modifier = Modifier.fillMaxSize(),
                factory = { ctx ->
                    val sensorOrientation = resolveBackCameraSensorOrientation(ctx)
                    var latestBufferSize: Size? = null
                    TextureView(ctx).apply {
                        surfaceTextureListener = object : TextureView.SurfaceTextureListener {
                            override fun onSurfaceTextureAvailable(st: SurfaceTexture, width: Int, height: Int) {
                                bindCameraToTexture(
                                    context = ctx,
                                    lifecycleOwner = lifecycleOwner,
                                    surfaceTexture = st,
                                    analysisExecutor = analysisExecutor,
                                    reader = zxingReader,
                                    delivered = delivered,
                                    onProviderReady = { boundProvider = it },
                                    onSurfaceCreated = { s ->
                                        activeSurface?.release()
                                        activeSurface = s
                                    },
                                    onBufferResolutionReady = { res ->
                                        latestBufferSize = res
                                        post { applyTextureTransform(this@apply, res, sensorOrientation) }
                                    },
                                    onDecoded = { text ->
                                        post { onResult(text) }
                                    },
                                    onError = { msg ->
                                        post { scanError = msg }
                                    },
                                )
                            }

                            override fun onSurfaceTextureSizeChanged(st: SurfaceTexture, w: Int, h: Int) {
                                latestBufferSize?.let { res ->
                                    post { applyTextureTransform(this@apply, res, sensorOrientation) }
                                }
                            }

                            override fun onSurfaceTextureDestroyed(st: SurfaceTexture): Boolean {
                                runCatching { boundProvider?.unbindAll() }
                                activeSurface?.release()
                                activeSurface = null
                                return true
                            }
                            override fun onSurfaceTextureUpdated(st: SurfaceTexture) = Unit
                        }
                    }
                },
            )
        } else {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.padding(24.dp)) {
                    Text("需要相机权限以实时扫码", color = Color.White, fontSize = 16.sp, fontWeight = FontWeight.Medium)
                    Spacer(Modifier.height(12.dp))
                    Button(onClick = { permLauncher.launch(Manifest.permission.CAMERA) }) {
                        Text("授权相机")
                    }
                }
            }
        }

        // Top overlay bar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .align(Alignment.TopCenter)
                .padding(horizontal = 16.dp, vertical = 12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = "扫二维码同步 / 导入",
                color = Color.White,
                fontSize = 18.sp,
                fontWeight = FontWeight.SemiBold,
            )
            IconButton(onClick = onClose) {
                Icon(CatIcons.Close, contentDescription = "关闭扫码", tint = Color.White)
            }
        }

        // Center scan reticle
        Box(
            modifier = Modifier
                .size(240.dp)
                .align(Alignment.Center)
                .border(2.dp, Color(0xFF4CE0B3), RoundedCornerShape(20.dp))
        )

        // Bottom hint & gallery picker
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .align(Alignment.BottomCenter)
                .padding(horizontal = 24.dp, vertical = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            if (!scanError.isNullOrBlank()) {
                Text(
                    text = scanError!!,
                    color = Color(0xFFFF8A95),
                    fontSize = 13.sp,
                    modifier = Modifier.padding(bottom = 10.dp),
                )
            }
            Text(
                text = "支持猫云同步码、中转码、订阅链接及标准节点二维码",
                color = Color.White.copy(alpha = 0.85f),
                fontSize = 13.sp,
            )
            Spacer(Modifier.height(14.dp))
            OutlinedButton(
                onClick = { galleryLauncher.launch("image/*") },
                shape = RoundedCornerShape(14.dp),
            ) {
                Text("从相册选图识别", color = Color.White)
            }
        }
    }
}

private fun resolveBackCameraSensorOrientation(context: Context): Int {
    return runCatching {
        val cm = context.getSystemService(Context.CAMERA_SERVICE) as? CameraManager ?: return@runCatching 90
        for (cameraId in cm.cameraIdList) {
            val chars = cm.getCameraCharacteristics(cameraId)
            if (chars.get(CameraCharacteristics.LENS_FACING) == CameraCharacteristics.LENS_FACING_BACK) {
                return@runCatching chars.get(CameraCharacteristics.SENSOR_ORIENTATION) ?: 90
            }
        }
        90
    }.getOrDefault(90)
}

/**
 * Computes a center-crop aspect-ratio & display-rotation correction [Matrix] for a raw [TextureView]
 * fed by CameraX [Preview].
 *
 * Camera2 applies a baseline sensor-orientation rotation into the BufferQueue so the image is upright
 * in the device's natural orientation (`Surface.ROTATION_0`), while [bufferSize] remains in sensor
 * coordinates. Using [sensorOrientation] we first derive the upright natural dimensions, undo
 * TextureView's default stretch, counter-rotate by `-displayDegrees` for any display rotation, and
 * finally center-crop uniformly so the viewfinder fills the container with zero distortion.
 */
private fun applyTextureTransform(
    textureView: TextureView,
    bufferSize: Size,
    sensorOrientation: Int,
) {
    val viewW = textureView.width.toFloat()
    val viewH = textureView.height.toFloat()
    if (viewW <= 0f || viewH <= 0f || bufferSize.width <= 0 || bufferSize.height <= 0) return

    val sensorSwapped = (sensorOrientation % 180) != 0
    val naturalW = if (sensorSwapped) bufferSize.height.toFloat() else bufferSize.width.toFloat()
    val naturalH = if (sensorSwapped) bufferSize.width.toFloat() else bufferSize.height.toFloat()

    val displayRotation = textureView.display?.rotation ?: Surface.ROTATION_0
    val displayDegrees = when (displayRotation) {
        Surface.ROTATION_90 -> 90
        Surface.ROTATION_180 -> 180
        Surface.ROTATION_270 -> 270
        else -> 0
    }

    val cx = viewW / 2f
    val cy = viewH / 2f
    val matrix = Matrix()
    // 1. Undo TextureView's default non-uniform stretch back to true natural aspect ratio
    matrix.postScale(naturalW / viewW, naturalH / viewH, cx, cy)
    // 2. Counter-rotate for current display orientation
    if (displayDegrees != 0) {
        matrix.postRotate((-displayDegrees).toFloat(), cx, cy)
    }
    // 3. Uniform center-crop scale so the rotated preview fills the entire TextureView without bars
    val displaySwapped = (displayDegrees % 180) != 0
    val contentW = if (displaySwapped) naturalH else naturalW
    val contentH = if (displaySwapped) naturalW else naturalH
    val fillScale = maxOf(viewW / contentW, viewH / contentH)
    matrix.postScale(fillScale, fillScale, cx, cy)

    textureView.setTransform(matrix)
}

private fun bindCameraToTexture(
    context: Context,
    lifecycleOwner: LifecycleOwner,
    surfaceTexture: SurfaceTexture,
    analysisExecutor: java.util.concurrent.ExecutorService,
    reader: MultiFormatReader,
    delivered: AtomicBoolean,
    onProviderReady: (ProcessCameraProvider) -> Unit,
    onSurfaceCreated: (Surface) -> Unit,
    onBufferResolutionReady: (Size) -> Unit,
    onDecoded: (String) -> Unit,
    onError: (String) -> Unit,
) {
    val mainExecutor = ContextCompat.getMainExecutor(context)
    val future = ProcessCameraProvider.getInstance(context)
    future.addListener({
        try {
            val provider = future.get()
            onProviderReady(provider)

            val preview = Preview.Builder().build()
            preview.setSurfaceProvider { request ->
                val res = request.resolution
                surfaceTexture.setDefaultBufferSize(res.width, res.height)
                onBufferResolutionReady(res)
                val surface = Surface(surfaceTexture)
                onSurfaceCreated(surface)
                request.provideSurface(surface, mainExecutor) {
                    runCatching { surface.release() }
                }
            }

            val analysis = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
            analysis.setAnalyzer(analysisExecutor) { imageProxy ->
                decodeCameraFrame(imageProxy, reader, delivered, onDecoded)
            }

            provider.unbindAll()
            provider.bindToLifecycle(
                lifecycleOwner,
                CameraSelector.DEFAULT_BACK_CAMERA,
                preview,
                analysis,
            )
        } catch (t: Throwable) {
            onError("启动相机失败：${t.message ?: "请检查相机权限"}")
        }
    }, mainExecutor)
}

private fun decodeCameraFrame(
    imageProxy: ImageProxy,
    reader: MultiFormatReader,
    delivered: AtomicBoolean,
    onDecoded: (String) -> Unit,
) {
    try {
        if (delivered.get()) return
        val yPlane = imageProxy.planes.firstOrNull() ?: return
        val buf = yPlane.buffer
        val rowStride = yPlane.rowStride
        val width = imageProxy.width
        val height = imageProxy.height
        val yBytes = ByteArray(width * height)
        if (rowStride == width) {
            buf.get(yBytes)
        } else {
            val rowBuf = ByteArray(rowStride)
            for (r in 0 until height) {
                val readLen = minOf(rowStride, buf.remaining())
                if (readLen < width) break
                buf.get(rowBuf, 0, readLen)
                System.arraycopy(rowBuf, 0, yBytes, r * width, width)
            }
        }
        val source = PlanarYUVLuminanceSource(yBytes, width, height, 0, 0, width, height, false)
        val bitmap = BinaryBitmap(HybridBinarizer(source))
        val text = runCatching { reader.decodeWithState(bitmap).text }.getOrNull()
        reader.reset()
        if (!text.isNullOrBlank() && delivered.compareAndSet(false, true)) {
            onDecoded(text)
        }
    } finally {
        imageProxy.close()
    }
}

private fun decodeGalleryImage(context: android.content.Context, uri: Uri): String? {
    val rawBitmap = context.contentResolver.openInputStream(uri)?.use { ins ->
        BitmapFactory.decodeStream(ins)
    } ?: return null

    val scaled = if (maxOf(rawBitmap.width, rawBitmap.height) > 1280) {
        val ratio = 1280f / maxOf(rawBitmap.width, rawBitmap.height)
        Bitmap.createScaledBitmap(
            rawBitmap,
            (rawBitmap.width * ratio).toInt().coerceAtLeast(1),
            (rawBitmap.height * ratio).toInt().coerceAtLeast(1),
            true,
        ).also { rawBitmap.recycle() }
    } else {
        rawBitmap
    }

    return try {
        val w = scaled.width
        val h = scaled.height
        val pixels = IntArray(w * h)
        scaled.getPixels(pixels, 0, w, 0, 0, w, h)
        QrBitmapGenerator.decodeFromRgbPixels(pixels, w, h)
    } finally {
        scaled.recycle()
    }
}
