package io.github.jurybu.catcloud.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.jurybu.catcloud.BuildConfig
import io.github.jurybu.catcloud.data.PerAppMode
import io.github.jurybu.catcloud.data.ThemePreference
import io.github.jurybu.catcloud.oem.OemKeepAliveHelper
import io.github.jurybu.catcloud.ui.theme.LocalCatPalette

@Composable
fun SettingsTab(
    state: CatCloudUiState,
    onOpenQrScan: () -> Unit,
    onOpenPinDialog: () -> Unit,
    onImportClipboard: () -> Unit,
    onPickFile: () -> Unit,
    onPushRelayBoxItem: (String) -> Unit,
    onDeleteRelayBoxItem: (String) -> Unit,
    onClearRelayBox: () -> Unit,
    onLoadInstalledApps: () -> Unit,
    onUpdatePerApp: (PerAppMode, List<String>) -> Unit,
    onSetTheme: (ThemePreference) -> Unit,
    onSetAutoStartOnBoot: (Boolean) -> Unit,
    onForceRestartCore: () -> Unit,
    onRefreshLogs: () -> Unit,
    onCopyDiagnostics: () -> Unit,
) {
    val palette = LocalCatPalette.current
    val context = LocalContext.current

    var showRestartConfirm by remember { mutableStateOf(false) }
    var showKeepAliveDialog by remember { mutableStateOf(false) }
    var showPerAppDialog by remember { mutableStateOf(false) }
    var showLogsDialog by remember { mutableStateOf(false) }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .background(palette.background)
            .padding(horizontal = 16.dp),
        contentPadding = PaddingValues(top = 12.dp, bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        item {
            Text("设置", color = palette.textPrimary, fontSize = 20.sp, fontWeight = FontWeight.Bold)
        }

        // Section 1: Cross-device encrypted sync & portable relay box
        item {
            SettingsGroupCard(title = "跨设备同步与随身接力箱") {
                SettingsRowItem(
                    title = "扫二维码同步 / 反推",
                    subtitle = "局域网极速直传、公网零知识票据或手机接力推给电脑",
                    onClick = onOpenQrScan,
                )
                HorizontalDivider(color = palette.border)
                SettingsRowItem(
                    title = "输入 6 位配对码拉取",
                    subtitle = "端到端加密配对，同步电脑端节点与设置",
                    onClick = onOpenPinDialog,
                )
                HorizontalDivider(color = palette.border)
                SettingsRowItem(
                    title = "从剪贴板识别",
                    subtitle = "仅在点击时按需读取，绝不静默弹窗",
                    onClick = onImportClipboard,
                )
                HorizontalDivider(color = palette.border)
                SettingsRowItem(
                    title = "选择本地文件导入",
                    subtitle = "支持 .zip 分享包、.ccsync 加密包与 .yaml 订阅",
                    onClick = onPickFile,
                )

                if (state.relayBoxItems.isNotEmpty()) {
                    HorizontalDivider(color = palette.border)
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 14.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                "随身接力箱（传输端到端加密）",
                                color = palette.textPrimary,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Medium,
                            )
                            Text(
                                "${state.relayBoxItems.size}/3 · 7天自动过期",
                                color = palette.textSecondary,
                                fontSize = 11.sp,
                            )
                        }
                        TextButton(onClick = onClearRelayBox) { Text("一键清空") }
                    }
                    state.relayBoxItems.forEach { box ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 14.dp, vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(box.name, color = palette.textPrimary, fontSize = 13.sp, fontWeight = FontWeight.Medium)
                                Text(
                                    "${box.nodeCount} 节点 · ${box.relayCount} 中转 · ${box.sizeBytes / 1024} KiB",
                                    color = palette.textSecondary,
                                    fontSize = 11.sp,
                                )
                            }
                            TextButton(onClick = { onPushRelayBoxItem(box.id) }) { Text("扫码推电脑") }
                            IconButton(onClick = { onDeleteRelayBoxItem(box.id) }) {
                                Icon(CatIcons.Delete, contentDescription = "删除", tint = palette.textSecondary, modifier = Modifier.size(16.dp))
                            }
                        }
                    }
                }
            }
        }

        // Section 2: Per-app VPN access control
        item {
            SettingsGroupCard(title = "访问控制（分应用代理）") {
                val modeDesc = when (state.settings.perAppMode) {
                    PerAppMode.ALL -> "全部应用走代理（猫猫云梯自身强制排除防环）"
                    PerAppMode.BYPASS -> "绕过已选 ${state.settings.perAppPackages.size} 个应用（推荐：网银/校园直连）"
                    PerAppMode.ALLOW -> "仅代理已选 ${state.settings.perAppPackages.size} 个应用"
                }
                SettingsRowItem(
                    title = "分应用代理规则",
                    subtitle = modeDesc,
                    onClick = {
                        onLoadInstalledApps()
                        showPerAppDialog = true
                    },
                )
            }
        }

        // Section 3: Appearance & OEM keep-alive (RedMagic / Huawei)
        item {
            SettingsGroupCard(title = "外观与后台保活") {
                Column(modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
                    Text("界面主题", color = palette.textPrimary, fontSize = 14.sp, fontWeight = FontWeight.Medium)
                    Spacer(Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        listOf(
                            ThemePreference.MIDNIGHT_BLUE to "午夜星蓝",
                            ThemePreference.DAWN_LIGHT to "晨曦浅色",
                            ThemePreference.SYSTEM to "跟随系统",
                        ).forEach { (pref, label) ->
                            FilterChip(
                                selected = state.settings.theme == pref,
                                onClick = { onSetTheme(pref) },
                                label = { Text(label, fontSize = 12.sp) },
                            )
                        }
                    }
                }
                HorizontalDivider(color = palette.border)
                SettingsRowItem(
                    title = "后台保活向导（${OemKeepAliveHelper.detectVendor().displayName}）",
                    subtitle = if (OemKeepAliveHelper.isIgnoringBatteryOptimizations(context)) {
                        "已开启电池白名单 · 点此检查厂商自启动"
                    } else {
                        "两步完成红魔 / 华为防杀后台配置"
                    },
                    onClick = { showKeepAliveDialog = true },
                )
                HorizontalDivider(color = palette.border)
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 14.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("开机自动恢复连接", color = palette.textPrimary, fontSize = 14.sp, fontWeight = FontWeight.Medium)
                        Text("默认关闭；仅当关机前处于已连接状态时恢复", color = palette.textSecondary, fontSize = 11.sp)
                    }
                    Switch(
                        checked = state.settings.autoStartOnBoot,
                        onCheckedChange = onSetAutoStartOnBoot,
                    )
                }
            }
        }

        // Section 4: Maintenance, Force Restart Core & Diagnostics
        item {
            SettingsGroupCard(title = "维护与诊断") {
                SettingsRowItem(
                    title = "强制重启核心",
                    subtitle = "清理僵死隧道连接并重新拉起内置 Mihomo 内核",
                    onClick = { showRestartConfirm = true },
                )
                HorizontalDivider(color = palette.border)
                SettingsRowItem(
                    title = "脱敏运行日志与诊断",
                    subtitle = "滚动限 <= 1 MiB，自动隐藏密码 / UUID / 密钥",
                    onClick = {
                        onRefreshLogs()
                        showLogsDialog = true
                    },
                )
                HorizontalDivider(color = palette.border)
                SettingsRowItem(
                    title = "关于猫猫云梯",
                    subtitle = "v${BuildConfig.VERSION_NAME} · 轻量双进程架构",
                    onClick = {},
                )
            }
        }
    }

    // Force restart confirmation dialog (Reference Image 1)
    if (showRestartConfirm) {
        AlertDialog(
            onDismissRequest = { showRestartConfirm = false },
            title = { Text("确定要强制重启核心吗？") },
            text = { Text("这将中断当前所有代理连接，清理内核状态并重新建立 VPN 隧道。") },
            confirmButton = {
                Button(onClick = {
                    showRestartConfirm = false
                    onForceRestartCore()
                }) { Text("确定重启") }
            },
            dismissButton = {
                TextButton(onClick = { showRestartConfirm = false }) { Text("取消") }
            },
        )
    }

    // OEM 2-step keep-alive wizard dialog
    if (showKeepAliveDialog) {
        AlertDialog(
            onDismissRequest = { showKeepAliveDialog = false },
            title = { Text("后台保活向导") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(OemKeepAliveHelper.vendorGuidanceText(), fontSize = 13.sp)
                    Button(
                        modifier = Modifier.fillMaxWidth(),
                        onClick = { OemKeepAliveHelper.openBatteryWhitelistSettings(context) },
                    ) { Text("第 1 步：加入电池优化白名单") }
                    OutlinedButton(
                        modifier = Modifier.fillMaxWidth(),
                        onClick = { OemKeepAliveHelper.openOemAutoStartSettings(context) },
                    ) { Text("第 2 步：打开厂商自启动与后台管理") }
                }
            },
            confirmButton = {
                TextButton(onClick = { showKeepAliveDialog = false }) { Text("完成") }
            },
        )
    }

    // Per-app access control dialog
    if (showPerAppDialog) {
        var mode by remember { mutableStateOf(state.settings.perAppMode) }
        var selectedPkgs by remember { mutableStateOf(state.settings.perAppPackages.toSet()) }
        var query by remember { mutableStateOf("") }
        val filtered = remember(state.installedApps, query) {
            val q = query.trim().lowercase()
            state.installedApps.filter {
                q.isEmpty() || it.label.lowercase().contains(q) || it.packageName.lowercase().contains(q)
            }
        }

        AlertDialog(
            onDismissRequest = { showPerAppDialog = false },
            title = { Text("访问控制（分应用代理）") },
            text = {
                Column(modifier = Modifier.fillMaxWidth()) {
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        listOf(
                            PerAppMode.ALL to "全部",
                            PerAppMode.BYPASS to "绕过已选",
                            PerAppMode.ALLOW to "仅已选",
                        ).forEach { (m, lbl) ->
                            FilterChip(
                                selected = mode == m,
                                onClick = { mode = m },
                                label = { Text(lbl, fontSize = 12.sp) },
                            )
                        }
                    }
                    if (mode != PerAppMode.ALL) {
                        Spacer(Modifier.height(6.dp))
                        OutlinedTextField(
                            value = query,
                            onValueChange = { query = it },
                            placeholder = { Text("搜索应用名或包名") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Spacer(Modifier.height(6.dp))
                        LazyColumn(modifier = Modifier.height(240.dp)) {
                            items(filtered, key = { it.packageName }) { app ->
                                val checked = selectedPkgs.contains(app.packageName)
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable {
                                            selectedPkgs = if (checked) selectedPkgs - app.packageName else selectedPkgs + app.packageName
                                        }
                                        .padding(vertical = 4.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    Checkbox(
                                        checked = checked,
                                        onCheckedChange = { c ->
                                            selectedPkgs = if (c) selectedPkgs + app.packageName else selectedPkgs - app.packageName
                                        },
                                    )
                                    Column {
                                        Text(app.label, fontSize = 13.sp, maxLines = 1)
                                        Text(app.packageName, fontSize = 10.sp, color = palette.textSecondary, maxLines = 1)
                                    }
                                }
                            }
                        }
                    }
                }
            },
            confirmButton = {
                Button(onClick = {
                    onUpdatePerApp(mode, selectedPkgs.toList())
                    showPerAppDialog = false
                }) { Text("保存") }
            },
            dismissButton = {
                TextButton(onClick = { showPerAppDialog = false }) { Text("取消") }
            },
        )
    }

    // Sanitized logs & copy diagnostics dialog
    if (showLogsDialog) {
        AlertDialog(
            onDismissRequest = { showLogsDialog = false },
            title = { Text("脱敏运行日志") },
            text = {
                LazyColumn(modifier = Modifier.height(280.dp)) {
                    if (state.recentLogs.isEmpty()) {
                        item { Text("暂无运行日志", fontSize = 12.sp, color = palette.textSecondary) }
                    } else {
                        items(state.recentLogs) { line ->
                            Text(line, fontSize = 11.sp, color = palette.textPrimary)
                        }
                    }
                }
            },
            confirmButton = {
                Button(onClick = {
                    onCopyDiagnostics()
                    showLogsDialog = false
                }) {
                    Icon(CatIcons.Copy, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("复制诊断摘要")
                }
            },
            dismissButton = {
                TextButton(onClick = { showLogsDialog = false }) { Text("关闭") }
            },
        )
    }
}

@Composable
private fun SettingsGroupCard(
    title: String,
    content: @Composable () -> Unit,
) {
    val palette = LocalCatPalette.current
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = title,
            color = palette.textSecondary,
            fontSize = 12.sp,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(start = 6.dp, bottom = 6.dp),
        )
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            color = palette.surface,
            border = BorderStroke(1.dp, palette.border),
        ) {
            Column(modifier = Modifier.fillMaxWidth()) {
                content()
            }
        }
    }
}

@Composable
private fun SettingsRowItem(
    title: String,
    subtitle: String,
    onClick: () -> Unit,
) {
    val palette = LocalCatPalette.current
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() }
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(title, color = palette.textPrimary, fontSize = 14.sp, fontWeight = FontWeight.Medium)
            Spacer(Modifier.height(2.dp))
            Text(subtitle, color = palette.textSecondary, fontSize = 11.sp)
        }
        Icon(
            imageVector = CatIcons.ChevronRight,
            contentDescription = null,
            tint = palette.textSecondary,
            modifier = Modifier.size(18.dp),
        )
    }
}
