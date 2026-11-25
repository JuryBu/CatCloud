package io.github.jurybu.catcloud.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.jurybu.catcloud.data.RouteMode
import io.github.jurybu.catcloud.ui.theme.LocalCatPalette
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NodesTab(
    state: CatCloudUiState,
    initialSubTab: Int = 0,
    onSelectSingleNode: (String) -> Unit,
    onSelectGroup: (String) -> Unit,
    onDeleteNode: (String) -> Unit,
    onTestAllLatencies: () -> Unit,
    onStartThroughputTest: (Set<String>, Boolean) -> Unit,
    onStopSpeedTest: () -> Unit,
    onSelectActiveRelay: (String) -> Unit,
    onTogglePreAccelAutoFailover: (Boolean) -> Unit,
    onDeleteRelay: (String) -> Unit,
    onOpenQrScan: () -> Unit,
    onOpenPinDialog: () -> Unit,
    onImportClipboard: () -> Unit,
    onPickFile: () -> Unit,
) {
    val palette = LocalCatPalette.current
    var subTab by remember(initialSubTab) { mutableIntStateOf(initialSubTab) }
    var selectedRegion by remember { mutableStateOf("ALL") }
    var multiSelectMode by remember { mutableStateOf(false) }
    var checkedIds by remember { mutableStateOf(setOf<String>()) }
    var throughputWithPreAccel by remember { mutableStateOf(state.settings.preaccelEnabled) }
    var showImportSheet by remember { mutableStateOf(false) }

    val regions = remember(state.nodes) {
        listOf("ALL") + state.nodes.map { it.regionCode }.distinct().sorted()
    }
    val filteredNodes = remember(state.nodes, selectedRegion) {
        state.nodes.filter { selectedRegion == "ALL" || it.regionCode == selectedRegion }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(palette.background)
            .padding(horizontal = 16.dp),
    ) {
        Spacer(Modifier.height(10.dp))

        // Header + actions
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text("节点与提速", color = palette.textPrimary, fontSize = 20.sp, fontWeight = FontWeight.Bold)
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (subTab == 0) {
                    TextButton(onClick = {
                        if (state.speedTestProgress.running) onStopSpeedTest() else onTestAllLatencies()
                    }) {
                        Text(if (state.speedTestProgress.running) "停止" else "测延迟")
                    }
                    TextButton(onClick = {
                        multiSelectMode = !multiSelectMode
                        if (!multiSelectMode) checkedIds = emptySet()
                    }) {
                        Text(if (multiSelectMode) "退出多选" else "测上下行")
                    }
                }
                IconButton(onClick = { showImportSheet = true }) {
                    Icon(CatIcons.Add, contentDescription = "导入与同步", tint = palette.accentStarBlue)
                }
            }
        }

        // 3-way segmented tabs: 全部节点 | 国内提速 | 多选组
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(14.dp),
            color = palette.surface,
            border = BorderStroke(1.dp, palette.border),
        ) {
            Row(modifier = Modifier.padding(4.dp), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                listOf("全部节点", "国内提速", "多选组").forEachIndexed { idx, label ->
                    val selected = subTab == idx
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .clip(RoundedCornerShape(10.dp))
                            .background(if (selected) palette.accentStarBlue else Color.Transparent)
                            .clickable { subTab = idx }
                            .padding(vertical = 8.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            text = label,
                            color = if (selected) Color.White else palette.textSecondary,
                            fontSize = 13.sp,
                            fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
                        )
                    }
                }
            }
        }

        // Speed test progress bar
        if (state.speedTestProgress.running) {
            Spacer(Modifier.height(8.dp))
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                color = palette.surfaceElevated,
            ) {
                Column(modifier = Modifier.padding(10.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            text = "${state.speedTestProgress.modeLabel} ${state.speedTestProgress.completed}/${state.speedTestProgress.total} ${state.speedTestProgress.currentNodeName}",
                            color = palette.textPrimary,
                            fontSize = 12.sp,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f),
                        )
                        TextButton(onClick = onStopSpeedTest) { Text("暂停") }
                    }
                    val progress = if (state.speedTestProgress.total > 0) {
                        state.speedTestProgress.completed.toFloat() / state.speedTestProgress.total.toFloat()
                    } else 0f
                    LinearProgressIndicator(progress = { progress }, modifier = Modifier.fillMaxWidth())
                }
            }
        }

        Spacer(Modifier.height(8.dp))

        when (subTab) {
            0 -> {
                // Region filter chips
                LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(regions, key = { it }) { r ->
                        FilterChip(
                            selected = selectedRegion == r,
                            onClick = { selectedRegion = r },
                            label = { Text(if (r == "ALL") "全部 (${state.nodes.size})" else r) },
                        )
                    }
                }

                // Multi-select serial throughput action bar
                if (multiSelectMode) {
                    Spacer(Modifier.height(6.dp))
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(14.dp),
                        color = palette.surface,
                        border = BorderStroke(1.dp, palette.border),
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 12.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text("443 提速对照", color = palette.textSecondary, fontSize = 12.sp)
                                Spacer(Modifier.width(6.dp))
                                Switch(
                                    checked = throughputWithPreAccel,
                                    onCheckedChange = { throughputWithPreAccel = it },
                                )
                            }
                            Button(
                                enabled = checkedIds.isNotEmpty() && !state.speedTestProgress.running,
                                onClick = { onStartThroughputTest(checkedIds, throughputWithPreAccel) },
                            ) {
                                Text("串行测速 (${checkedIds.size})")
                            }
                        }
                    }
                }

                Spacer(Modifier.height(8.dp))

                if (filteredNodes.isEmpty()) {
                    EmptyPlaceholder("暂无节点，点击右上角「+」扫码同步或导入") {
                        showImportSheet = true
                    }
                } else {
                    LazyColumn(
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                        contentPadding = PaddingValues(bottom = 16.dp),
                    ) {
                        items(filteredNodes, key = { it.id }) { node ->
                            val isActive = state.settings.routeMode == RouteMode.SINGLE &&
                                state.settings.activeSingleNodeId == node.id
                            val isChecked = checkedIds.contains(node.id)
                            Surface(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        if (multiSelectMode) {
                                            checkedIds = if (isChecked) checkedIds - node.id else checkedIds + node.id
                                        } else {
                                            onSelectSingleNode(node.id)
                                        }
                                    },
                                shape = RoundedCornerShape(14.dp),
                                color = if (isActive) palette.mintSingleBg else palette.surface,
                                border = BorderStroke(
                                    if (isActive) 1.5.dp else 1.dp,
                                    if (isActive) palette.mintSingle else palette.border,
                                ),
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(horizontal = 12.dp, vertical = 10.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    if (multiSelectMode) {
                                        Checkbox(
                                            checked = isChecked,
                                            onCheckedChange = { c ->
                                                checkedIds = if (c) checkedIds + node.id else checkedIds - node.id
                                            },
                                        )
                                    }
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = node.name,
                                            color = palette.textPrimary,
                                            fontSize = 14.sp,
                                            fontWeight = FontWeight.Medium,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis,
                                        )
                                        Spacer(Modifier.height(3.dp))
                                        val speedTag = buildString {
                                            append("${node.protocol.uppercase()} · ${node.regionCode}")
                                            if (node.lastDownMbps != null || node.lastUpMbps != null) {
                                                append(" · ")
                                                node.lastDownMbps?.let {
                                                    append("↓${String.format(Locale.US, "%.1f", it)}")
                                                }
                                                node.lastUpMbps?.let {
                                                    append(" ↑${String.format(Locale.US, "%.1f", it)}")
                                                }
                                                append(" Mbps")
                                            }
                                        }
                                        Text(speedTag, color = palette.textSecondary, fontSize = 11.sp)
                                    }
                                    Text(
                                        text = node.lastLatencyMs?.let { "${it}ms" } ?: "--",
                                        color = when {
                                            node.lastLatencyMs == null -> palette.textSecondary
                                            node.lastLatencyMs < 260 -> palette.latencyGood
                                            else -> palette.latencyWarn
                                        },
                                        fontSize = 12.sp,
                                        fontWeight = FontWeight.SemiBold,
                                    )
                                    if (!multiSelectMode) {
                                        IconButton(onClick = { onDeleteNode(node.id) }) {
                                            Icon(
                                                CatIcons.Delete,
                                                contentDescription = "删除节点",
                                                tint = palette.textSecondary,
                                                modifier = Modifier.size(18.dp),
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            1 -> {
                // Domestic :443 Pre-Acceleration relays
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(14.dp),
                    color = palette.surface,
                    border = BorderStroke(1.dp, palette.border),
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 14.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("国内 204 自动双活", color = palette.textPrimary, fontSize = 14.sp, fontWeight = FontWeight.Medium)
                            Text("纯 IP :443 禁 SNI，异常自动 fail-open 直连", color = palette.textSecondary, fontSize = 11.sp)
                        }
                        Switch(
                            checked = state.settings.preaccelAutoFailover,
                            onCheckedChange = onTogglePreAccelAutoFailover,
                        )
                    }
                }
                Spacer(Modifier.height(10.dp))
                if (state.relays.isEmpty()) {
                    EmptyPlaceholder("暂无国内 :443 提速中转，支持扫码或粘贴 mmrelay://v1 导入") {
                        showImportSheet = true
                    }
                } else {
                    LazyColumn(
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                        contentPadding = PaddingValues(bottom = 16.dp),
                    ) {
                        items(state.relays, key = { it.id }) { relay ->
                            val isPrimary = state.settings.preaccelActiveRelayId == relay.id ||
                                (state.settings.preaccelActiveRelayId == null && relay == state.relays.firstOrNull())
                            Surface(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable { onSelectActiveRelay(relay.id) },
                                shape = RoundedCornerShape(14.dp),
                                color = if (isPrimary) palette.warmGoldGroupBg else palette.surface,
                                border = BorderStroke(
                                    if (isPrimary) 1.5.dp else 1.dp,
                                    if (isPrimary) palette.warmGoldGroup else palette.border,
                                ),
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(horizontal = 14.dp, vertical = 12.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = if (isPrimary) "★ ${relay.name}" else relay.name,
                                            color = palette.textPrimary,
                                            fontSize = 14.sp,
                                            fontWeight = FontWeight.SemiBold,
                                        )
                                        Text(
                                            text = "${relay.protocol.uppercase()} :${relay.port} · ${relay.region.ifBlank { "国内" }}",
                                            color = palette.textSecondary,
                                            fontSize = 12.sp,
                                        )
                                    }
                                    IconButton(onClick = { onDeleteRelay(relay.id) }) {
                                        Icon(CatIcons.Delete, contentDescription = "删除中转", tint = palette.textSecondary, modifier = Modifier.size(18.dp))
                                    }
                                }
                            }
                        }
                    }
                }
            }

            2 -> {
                // Smart multi-select groups
                if (state.groups.isEmpty()) {
                    EmptyPlaceholder("暂无智能多选组，从桌面端扫码同步即可自动增量合并") {
                        showImportSheet = true
                    }
                } else {
                    LazyColumn(
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                        contentPadding = PaddingValues(bottom = 16.dp),
                    ) {
                        items(state.groups, key = { it.id }) { group ->
                            val isActive = state.settings.routeMode == RouteMode.GROUP &&
                                state.settings.activeGroupId == group.id
                            val activeNodeName = group.activeNodeId?.let { aid ->
                                state.nodes.firstOrNull { it.id == aid }?.name
                            } ?: "自动择优"
                            Surface(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable { onSelectGroup(group.id) },
                                shape = RoundedCornerShape(14.dp),
                                color = if (isActive) palette.warmGoldGroupBg else palette.surface,
                                border = BorderStroke(
                                    if (isActive) 1.5.dp else 1.dp,
                                    if (isActive) palette.warmGoldGroup else palette.border,
                                ),
                            ) {
                                Column(modifier = Modifier.padding(14.dp)) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically,
                                    ) {
                                        Text(group.name, color = palette.textPrimary, fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
                                        Text(
                                            text = if (isActive) "当前生效" else "${group.memberNodeIds.size} 个成员",
                                            color = if (isActive) palette.warmGoldGroup else palette.textSecondary,
                                            fontSize = 12.sp,
                                        )
                                    }
                                    Spacer(Modifier.height(4.dp))
                                    Text(
                                        text = "活跃节点：$activeNodeName · 模式：${group.mode}",
                                        color = palette.textSecondary,
                                        fontSize = 12.sp,
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (showImportSheet) {
        ModalBottomSheet(
            onDismissRequest = { showImportSheet = false },
            containerColor = palette.surface,
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .navigationBarsPadding()
                    .padding(horizontal = 20.dp)
                    .padding(bottom = 20.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text("导入与多端扫码同步", color = palette.textPrimary, fontSize = 18.sp, fontWeight = FontWeight.Bold)
                Text(
                    "端到端加密直传，仅按需读取剪贴板，绝不静默偷读。",
                    color = palette.textSecondary,
                    fontSize = 12.sp,
                )
                Button(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(14.dp),
                    onClick = {
                        showImportSheet = false
                        onOpenQrScan()
                    },
                ) {
                    Icon(CatIcons.QrScan, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("扫二维码同步（局域网 / 接力 / 票据）")
                }
                OutlinedButton(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(14.dp),
                    onClick = {
                        showImportSheet = false
                        onOpenPinDialog()
                    },
                ) {
                    Text("输入 6 位一次性配对码拉取")
                }
                OutlinedButton(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(14.dp),
                    onClick = {
                        showImportSheet = false
                        onImportClipboard()
                    },
                ) {
                    Text("从剪贴板识别（节点 / 订阅 / mmrelay）")
                }
                OutlinedButton(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(14.dp),
                    onClick = {
                        showImportSheet = false
                        onPickFile()
                    },
                ) {
                    Text("选择本地文件（.zip / .ccsync / .yaml）")
                }
            }
        }
    }
}

@Composable
private fun EmptyPlaceholder(message: String, onAction: () -> Unit) {
    val palette = LocalCatPalette.current
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center,
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.padding(24.dp)) {
            Text(message, color = palette.textSecondary, fontSize = 13.sp)
            Spacer(Modifier.height(12.dp))
            OutlinedButton(onClick = onAction, shape = RoundedCornerShape(14.dp)) {
                Text("立即扫码同步 / 导入")
            }
        }
    }
}
