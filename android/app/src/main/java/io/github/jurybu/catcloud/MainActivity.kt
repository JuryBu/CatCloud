package io.github.jurybu.catcloud

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import io.github.jurybu.catcloud.oem.RefreshRateHelper
import io.github.jurybu.catcloud.ui.AppViewModel
import io.github.jurybu.catcloud.ui.CatIcons
import io.github.jurybu.catcloud.ui.HomeTab
import io.github.jurybu.catcloud.ui.NodesTab
import io.github.jurybu.catcloud.ui.QrScanScreen
import io.github.jurybu.catcloud.ui.SettingsTab
import io.github.jurybu.catcloud.ui.theme.CatCloudTheme
import io.github.jurybu.catcloud.ui.theme.LocalCatPalette

class MainActivity : ComponentActivity() {

    private lateinit var viewModel: AppViewModel
    private var requestedPostNotifOnce = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        RefreshRateHelper.unlockHighRefreshRate(this)
        viewModel = AppViewModel(applicationContext)
        handleExternalIntent(intent)

        setContent {
            val uiState by viewModel.state.collectAsState()
            CatCloudTheme(preference = uiState.settings.theme) {
                CatCloudRootScreen(
                    viewModel = viewModel,
                    onRequestConnect = { startConnectFlow ->
                        requestNotificationsThenConnect(startConnectFlow)
                    },
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleExternalIntent(intent)
    }

    override fun onDestroy() {
        viewModel.close()
        super.onDestroy()
    }

    private fun requestNotificationsThenConnect(launchVpnPrepare: () -> Unit) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !requestedPostNotifOnce) {
            val granted = ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS,
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                requestedPostNotifOnce = true
                requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 2033)
            }
        }
        launchVpnPrepare()
    }

    private fun handleExternalIntent(intent: Intent?) {
        if (intent == null) return
        when (intent.action) {
            Intent.ACTION_SEND -> {
                val streamUri: Uri? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra(Intent.EXTRA_STREAM)
                } ?: intent.clipData?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.uri
                if (streamUri != null) {
                    viewModel.importFromContentUri(streamUri)
                    return
                }
                val sharedText = intent.getStringExtra(Intent.EXTRA_TEXT)
                    ?: intent.clipData?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(this)?.toString()
                if (!sharedText.isNullOrBlank()) {
                    val installUrl = AppViewModel.extractInstallConfigSubscriptionUrl(sharedText)
                    if (!installUrl.isNullOrBlank()) {
                        viewModel.importSubscriptionUrl(installUrl, sourceLabel = "系统分享")
                    } else {
                        viewModel.handleScannedOrPastedText(sharedText, sourceLabel = "系统分享")
                    }
                }
            }
            Intent.ACTION_VIEW -> {
                val data = intent.data ?: return
                val rawStr = data.toString()
                when (data.scheme?.lowercase().orEmpty()) {
                    "clash", "catcloud" -> {
                        val subUrl = AppViewModel.extractInstallConfigSubscriptionUrl(rawStr)
                        if (!subUrl.isNullOrBlank()) {
                            viewModel.importSubscriptionUrl(subUrl, sourceLabel = "外部订阅")
                        } else {
                            viewModel.handleScannedOrPastedText(rawStr, sourceLabel = "外部唤起")
                        }
                    }
                    "catcloud-sync", "mmrelay" -> {
                        viewModel.handleScannedOrPastedText(rawStr, sourceLabel = "外部唤起")
                    }
                    "http", "https" -> {
                        viewModel.importSubscriptionUrl(rawStr, sourceLabel = "外部订阅")
                    }
                    "content", "file" -> {
                        viewModel.importFromContentUri(data)
                    }
                }
            }
        }
    }
}

@Composable
private fun CatCloudRootScreen(
    viewModel: AppViewModel,
    onRequestConnect: (launchVpnPrepare: () -> Unit) -> Unit,
) {
    val state by viewModel.state.collectAsState()
    val context = LocalContext.current
    val palette = LocalCatPalette.current
    val snackbarHostState = remember { SnackbarHostState() }

    var currentTab by remember { mutableIntStateOf(0) }
    var nodesInitialSubTab by remember { mutableIntStateOf(0) }
    var showQrScanner by remember { mutableStateOf(false) }
    var showPinDialog by remember { mutableStateOf(false) }

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { res ->
        if (res.resultCode == Activity.RESULT_OK) {
            viewModel.connectVpn()
        } else {
            viewModel.showToast("未授予 VPN 权限，无法启动隧道")
        }
    }

    val filePickerLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            viewModel.importFromContentUri(uri)
        }
    }

    val triggerVpnToggle = {
        if (state.vpnStatus.running) {
            viewModel.disconnectVpn()
        } else {
            onRequestConnect {
                val prep = VpnService.prepare(context)
                if (prep != null) {
                    vpnPermissionLauncher.launch(prep)
                } else {
                    viewModel.connectVpn()
                }
            }
        }
    }

    LaunchedEffect(state.toastMessage) {
        val msg = state.toastMessage ?: return@LaunchedEffect
        snackbarHostState.showSnackbar(msg)
        viewModel.clearToast()
    }

    if (showQrScanner) {
        QrScanScreen(
            onResult = { text ->
                showQrScanner = false
                viewModel.handleScannedOrPastedText(text, sourceLabel = "扫码")
            },
            onClose = {
                showQrScanner = false
                viewModel.preparePushFromRelayBox(null)
            },
        )
        return
    }

    Scaffold(
        containerColor = palette.background,
        snackbarHost = { SnackbarHost(snackbarHostState) },
        bottomBar = {
            NavigationBar(containerColor = palette.surface) {
                NavigationBarItem(
                    selected = currentTab == 0,
                    onClick = { currentTab = 0 },
                    icon = { Icon(CatIcons.Home, contentDescription = "首页") },
                    label = { Text("首页") },
                )
                NavigationBarItem(
                    selected = currentTab == 1,
                    onClick = { currentTab = 1 },
                    icon = { Icon(CatIcons.Nodes, contentDescription = "节点") },
                    label = { Text("节点") },
                )
                NavigationBarItem(
                    selected = currentTab == 2,
                    onClick = { currentTab = 2 },
                    icon = { Icon(CatIcons.Settings, contentDescription = "设置") },
                    label = { Text("设置") },
                )
            }
        },
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            when (currentTab) {
                0 -> HomeTab(
                    state = state,
                    onToggleConnect = triggerVpnToggle,
                    onOpenQrScan = {
                        viewModel.preparePushFromRelayBox(null)
                        showQrScanner = true
                    },
                    onSelectSingleNode = viewModel::selectSingleNode,
                    onSelectGroup = viewModel::selectMultiGroup,
                    onSetProxyMode = viewModel::setProxyMode,
                    onTogglePreAccel = viewModel::togglePreAccel,
                    onNavigateToRelays = {
                        nodesInitialSubTab = 1
                        currentTab = 1
                    },
                    onTestAllLatencies = viewModel::testAllLatencies,
                )
                1 -> NodesTab(
                    state = state,
                    initialSubTab = nodesInitialSubTab,
                    onSelectSingleNode = viewModel::selectSingleNode,
                    onSelectGroup = viewModel::selectMultiGroup,
                    onDeleteNode = viewModel::deleteNode,
                    onTestAllLatencies = viewModel::testAllLatencies,
                    onStartThroughputTest = viewModel::startSerialThroughputTest,
                    onStopSpeedTest = viewModel::stopSpeedTest,
                    onSelectActiveRelay = viewModel::selectActiveRelay,
                    onTogglePreAccelAutoFailover = viewModel::togglePreAccelAutoFailover,
                    onDeleteRelay = viewModel::deleteRelay,
                    onProbeRelaysLatency = viewModel::probeAllRelaysLatency,
                    onOpenQrScan = {
                        viewModel.preparePushFromRelayBox(null)
                        showQrScanner = true
                    },
                    onOpenPinDialog = { showPinDialog = true },
                    onImportClipboard = viewModel::importFromClipboardOnDemand,
                    onPickFile = { filePickerLauncher.launch(arrayOf("*/*")) },
                )
                2 -> SettingsTab(
                    state = state,
                    onOpenQrScan = {
                        viewModel.preparePushFromRelayBox(null)
                        showQrScanner = true
                    },
                    onOpenPinDialog = { showPinDialog = true },
                    onImportClipboard = viewModel::importFromClipboardOnDemand,
                    onPickFile = { filePickerLauncher.launch(arrayOf("*/*")) },
                    onPushRelayBoxItem = { boxId ->
                        viewModel.preparePushFromRelayBox(boxId)
                        showQrScanner = true
                    },
                    onDeleteRelayBoxItem = viewModel::deleteRelayBoxItem,
                    onClearRelayBox = viewModel::clearRelayBox,
                    onLoadInstalledApps = viewModel::loadInstalledAppsIfNeeded,
                    onUpdatePerApp = viewModel::updatePerAppControl,
                    onSetTheme = viewModel::setTheme,
                    onSetAutoStartOnBoot = viewModel::setAutoStartOnBoot,
                    onForceRestartCore = viewModel::forceRestartCore,
                    onRefreshLogs = viewModel::refreshLogs,
                    onCopyDiagnostics = viewModel::copyDiagnosticsToClipboard,
                )
            }
        }
    }

    // 6-digit PIN LAN sync dialog
    if (showPinDialog) {
        var hostText by remember { mutableStateOf("") }
        var portText by remember { mutableStateOf("27999") }
        var pinText by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { showPinDialog = false },
            title = { Text("输入 6 位配对码拉取") },
            text = {
                Column {
                    OutlinedTextField(
                        value = hostText,
                        onValueChange = { hostText = it },
                        label = { Text("电脑局域网 IP 或自定义地址") },
                        placeholder = { Text("例如 192.168.1.10") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = portText,
                        onValueChange = { portText = it },
                        label = { Text("端口") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = pinText,
                        onValueChange = { pinText = it },
                        label = { Text("6 位一次性配对码") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            },
            confirmButton = {
                Button(onClick = {
                    val port = portText.trim().toIntOrNull() ?: 27999
                    showPinDialog = false
                    viewModel.pullWithSixDigitPin(hostText.trim(), port, pinText.trim())
                }) { Text("拉取并预览") }
            },
            dismissButton = {
                TextButton(onClick = { showPinDialog = false }) { Text("取消") }
            },
        )
    }

    // Pending share bundle preview & confirm dialog
    state.pendingImportBundle?.let { bundle ->
        var saveToBox by remember { mutableStateOf(true) }
        AlertDialog(
            onDismissRequest = viewModel::dismissPendingImport,
            title = { Text("确认导入配置包") },
            text = {
                Column {
                    Text("包名：${bundle.preview.manifest.name}", fontSize = 14.sp)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "包含 ${bundle.preview.nodes.size} 个节点、${bundle.preview.relays.size} 条国内中转、${bundle.preview.groupsDoc?.groups?.size ?: 0} 个多选组",
                        fontSize = 13.sp,
                    )
                    Text("来源：${bundle.sourceLabel}", fontSize = 12.sp)
                    Spacer(Modifier.height(8.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = saveToBox, onCheckedChange = { saveToBox = it })
                        Text("同时暂存到随身接力箱（传输端到端加密，7天有效，方便推给另一台电脑）", fontSize = 12.sp)
                    }
                }
            },
            confirmButton = {
                Button(onClick = { viewModel.confirmImportPendingBundle(saveToBox) }) {
                    Text("增量合并导入")
                }
            },
            dismissButton = {
                TextButton(onClick = viewModel::dismissPendingImport) { Text("取消") }
            },
        )
    }

    // Pending offline .ccsync decryption dialog
    if (state.pendingCcsyncId != null) {
        var password by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = viewModel::dismissPendingCcsync,
            title = { Text("解密离线 .ccsync 配置包") },
            text = {
                Column {
                    Text("可扫描桌面生成的密钥二维码，或输入加密口令解锁。", fontSize = 13.sp)
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = password,
                        onValueChange = { password = it },
                        label = { Text("口令（可选）") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            },
            confirmButton = {
                Button(onClick = {
                    if (password.isNotEmpty()) {
                        viewModel.decryptPendingCcsyncWithPassword(password)
                    } else {
                        showQrScanner = true
                    }
                }) { Text(if (password.isNotEmpty()) "口令解密" else "扫密钥二维码") }
            },
            dismissButton = {
                TextButton(onClick = viewModel::dismissPendingCcsync) { Text("取消") }
            },
        )
    }
}
