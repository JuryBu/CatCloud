package io.github.jurybu.catcloud.ui

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.SurfaceTexture
import android.net.Uri
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
                                    onDecoded = { text ->
                                        post { onResult(text) }
                                    },
                                    onError = { msg ->
                                        post { scanError = msg }
                                    },
                                )
                            }

                            override fun onSurfaceTextureSizeChanged(st: SurfaceTexture, w: Int, h: Int) = Unit
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
                text = "支持猫云同步码、mmrelay 中转码及标准节点二维码",
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

private fun bindCameraToTexture(
    context: android.content.Context,
    lifecycleOwner: LifecycleOwner,
    surfaceTexture: SurfaceTexture,
    analysisExecutor: java.util.concurrent.ExecutorService,
    reader: MultiFormatReader,
    delivered: AtomicBoolean,
    onProviderReady: (ProcessCameraProvider) -> Unit,
    onSurfaceCreated: (Surface) -> Unit,
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
