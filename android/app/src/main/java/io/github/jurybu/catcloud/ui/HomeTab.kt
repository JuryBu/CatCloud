package io.github.jurybu.catcloud.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
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
import io.github.jurybu.catcloud.BuildConfig
import io.github.jurybu.catcloud.data.MultiGroupRecord
import io.github.jurybu.catcloud.data.ProxyMode
import io.github.jurybu.catcloud.data.ProxyNodeRecord
import io.github.jurybu.catcloud.data.RouteMode
import io.github.jurybu.catcloud.ui.theme.LocalCatPalette

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeTab(
    state: CatCloudUiState,
    onToggleConnect: () -> Unit,
    onOpenQrScan: () -> Unit,
    onSelectSingleNode: (String) -> Unit,
    onSelectGroup: (String) -> Unit,
    onSetProxyMode: (ProxyMode) -> Unit,
    onTogglePreAccel: (Boolean) -> Unit,
    onNavigateToRelays: () -> Unit,
    onTestAllLatencies: () -> Unit,
) {
    val palette = LocalCatPalette.current
    var showRouteSheet by remember { mutableStateOf(false) }

    val isGroupMode = state.settings.routeMode == RouteMode.GROUP && state.groups.isNotEmpty()
    val activeGroup: MultiGroupRecord? = if (isGroupMode) {
        state.groups.firstOrNull { it.id == state.settings.activeGroupId } ?: state.groups.firstOrNull()
    } else null
    val activeSingleNode: ProxyNodeRecord? = if (!isGroupMode) {
        state.nodes.firstOrNull { it.id == state.settings.activeSingleNodeId } ?: state.nodes.firstOrNull()
    } else {
        activeGroup?.activeNodeId?.let { aid -> state.nodes.firstOrNull { it.id == aid } }
    }

    val routeTitle = when {
        isGroupMode && activeGroup != null -> activeGroup.name
        activeSingleNode != null -> activeSingleNode.name
        else -> "尚未导入节点"
    }
    val routeBadgeText = if (isGroupMode) "智能多选组" else "单节点直选"
    val routeAccent = if (isGroupMode) palette.warmGoldGroup else palette.mintSingle
    val routeCardBg = if (isGroupMode) palette.warmGoldGroupBg else palette.mintSingleBg
    val activeLatency = activeSingleNode?.lastLatencyMs

    val activeRelay = state.relays.firstOrNull { it.id == state.settings.preaccelActiveRelayId && it.enabled }
        ?: state.relays.firstOrNull { it.enabled }
    val preAccelSubtext = when {
        !state.settings.preaccelEnabled -> "已关闭"
        activeRelay == null -> "未配置中转"
        state.settings.preaccelAutoFailover && state.relays.count { it.enabled } > 1 -> "双活 443"
        else -> activeRelay.name.take(8)
    }

    val isConnected = state.vpnStatus.running
    val ringColor by animateColorAsState(
        targetValue = if (isConnected) palette.mintSingle else palette.accentStarBlue,
        label = "powerRing",
    )

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(palette.background)
            .padding(horizontal = 20.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Spacer(Modifier.height(12.dp))

        // Top minimal header (zero notification bell; QR sync button on right)
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = "猫猫云梯",
                    color = palette.textPrimary,
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold,
                )
                Spacer(Modifier.width(8.dp))
                Surface(
                    color = palette.surfaceElevated,
                    shape = RoundedCornerShape(8.dp),
                ) {
                    Text(
                        text = "v${BuildConfig.VERSION_NAME}",
                        color = palette.textSecondary,
                        fontSize = 11.sp,
                        modifier = Modifier.padding(horizontal = 7.dp, vertical = 2.dp),
                    )
                }
            }
            IconButton(onClick = onOpenQrScan) {
                Icon(
                    imageVector = CatIcons.QrScan,
                    contentDescription = "扫码同步",
                    tint = palette.textPrimary,
                )
            }
        }

        Spacer(Modifier.height(18.dp))

        // Dual-tone current route card (Mint = Single, Warm Gold = Smart Multi-Group)
        Surface(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { showRouteSheet = true },
            shape = RoundedCornerShape(20.dp),
            color = routeCardBg,
            border = BorderStroke(1.dp, routeAccent.copy(alpha = 0.45f)),
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 14.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Box(
                    modifier = Modifier
                        .size(10.dp)
                        .clip(CircleShape)
                        .background(routeAccent)
                )
                Spacer(Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = routeBadgeText,
                        color = routeAccent,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Spacer(Modifier.height(2.dp))
                    Text(
                        text = routeTitle,
                        color = palette.textPrimary,
                        fontSize = 16.sp,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                if (activeLatency != null) {
                    Text(
                        text = "${activeLatency}ms",
                        color = if (activeLatency < 260) palette.latencyGood else palette.latencyWarn,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Medium,
                    )
                    Spacer(Modifier.width(6.dp))
                }
                Icon(
                    imageVector = CatIcons.ChevronRight,
                    contentDescription = "切换路线",
                    tint = palette.textSecondary,
                    modifier = Modifier.size(18.dp),
                )
            }
        }

        Spacer(Modifier.weight(1f))

        // Central large circular connect button
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier
                .size(164.dp)
                .clip(CircleShape)
                .background(ringColor.copy(alpha = if (isConnected) 0.16f else 0.10f))
                .border(3.dp, ringColor, CircleShape)
                .clickable(enabled = !state.busy) { onToggleConnect() },
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(
                    imageVector = CatIcons.Power,
                    contentDescription = if (isConnected) "断开连接" else "开始连接",
                    tint = ringColor,
                    modifier = Modifier.size(48.dp),
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    text = when {
                        state.busy -> "处理中…"
                        isConnected -> "已连接"
                        else -> "轻点连接"
                    },
                    color = palette.textPrimary,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.SemiBold,
                )
            }
        }

        Spacer(Modifier.height(14.dp))

        val modeLabel = if (state.settings.proxyMode == ProxyMode.RULE) "智能分流" else "全局代理"
        Text(
            text = if (isConnected) "已连接 · $modeLabel" else "未连接 · 零后台耗电",
            color = palette.textSecondary,
            fontSize = 13.sp,
        )

        Spacer(Modifier.weight(1f))

        // Routing mode dual capsule: 智能分流 | 全局代理
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            color = palette.surface,
            border = BorderStroke(1.dp, palette.border),
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(4.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                ModePillItem(
                    label = "智能分流",
                    selected = state.settings.proxyMode == ProxyMode.RULE,
                    modifier = Modifier.weight(1f),
                    onClick = { onSetProxyMode(ProxyMode.RULE) },
                )
                ModePillItem(
                    label = "全局代理",
                    selected = state.settings.proxyMode == ProxyMode.GLOBAL,
                    modifier = Modifier.weight(1f),
                    onClick = { onSetProxyMode(ProxyMode.GLOBAL) },
                )
            }
        }

        Spacer(Modifier.height(12.dp))

        // Domestic :443 Pre-Acceleration quick capsule
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(18.dp),
            color = palette.surface,
            border = BorderStroke(1.dp, palette.border),
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Row(
                    modifier = Modifier
                        .weight(1f)
                        .clickable { onNavigateToRelays() },
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Icon(
                        imageVector = CatIcons.Bolt,
                        contentDescription = null,
                        tint = if (state.settings.preaccelEnabled) palette.warmGoldGroup else palette.textSecondary,
                        modifier = Modifier.size(20.dp),
                    )
                    Spacer(Modifier.width(10.dp))
                    Column {
                        Text(
                            text = "国内提速",
                            color = palette.textPrimary,
                            fontSize = 15.sp,
                            fontWeight = FontWeight.Medium,
                        )
                        Text(
                            text = preAccelSubtext,
                            color = palette.textSecondary,
                            fontSize = 12.sp,
                            maxLines = 1,
                        )
                    }
                }
                Switch(
                    checked = state.settings.preaccelEnabled,
                    onCheckedChange = onTogglePreAccel,
                )
            }
        }

        Spacer(Modifier.height(16.dp))
    }

    if (showRouteSheet) {
        RoutePickerBottomSheet(
            state = state,
            onDismiss = { showRouteSheet = false },
            onSelectSingleNode = { id ->
                onSelectSingleNode(id)
                showRouteSheet = false
            },
            onSelectGroup = { id ->
                onSelectGroup(id)
                showRouteSheet = false
            },
            onTestLatencies = onTestAllLatencies,
        )
    }
}

@Composable
private fun ModePillItem(
    label: String,
    selected: Boolean,
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
) {
    val palette = LocalCatPalette.current
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(12.dp))
            .background(if (selected) palette.accentStarBlue else Color.Transparent)
            .clickable { onClick() }
            .padding(vertical = 11.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = label,
            color = if (selected) Color.White else palette.textSecondary,
            fontSize = 14.sp,
            fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun RoutePickerBottomSheet(
    state: CatCloudUiState,
    onDismiss: () -> Unit,
    onSelectSingleNode: (String) -> Unit,
    onSelectGroup: (String) -> Unit,
    onTestLatencies: () -> Unit,
) {
    val palette = LocalCatPalette.current
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    var selectedRegion by remember { mutableStateOf("ALL") }

    val regions = remember(state.nodes) {
        listOf("ALL") + state.nodes.map { it.regionCode }.distinct().sorted()
    }
    val visibleNodes = remember(state.nodes, selectedRegion) {
        state.nodes.filter { it.enabled && (selectedRegion == "ALL" || it.regionCode == selectedRegion) }
    }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = palette.surface,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .navigationBarsPadding()
                .padding(horizontal = 16.dp)
                .padding(bottom = 16.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = "选择路线",
                    color = palette.textPrimary,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold,
                )
                TextButton(onClick = onTestLatencies) {
                    Icon(CatIcons.Speed, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp))
                    Text(if (state.speedTestProgress.running) "测速中…" else "一键测延迟")
                }
            }

            // Smart multi-groups strip (Warm Gold)
            if (state.groups.isNotEmpty()) {
                Text("智能多选组", color = palette.textSecondary, fontSize = 12.sp, modifier = Modifier.padding(top = 4.dp, bottom = 6.dp))
                LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(state.groups, key = { it.id }) { g ->
                        val active = state.settings.routeMode == RouteMode.GROUP && state.settings.activeGroupId == g.id
                        FilterChip(
                            selected = active,
                            onClick = { onSelectGroup(g.id) },
                            label = { Text("${g.name} (${g.memberNodeIds.size})") },
                        )
                    }
                }
                Spacer(Modifier.height(10.dp))
            }

            // Region filter strip
            LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                items(regions, key = { it }) { reg ->
                    FilterChip(
                        selected = selectedRegion == reg,
                        onClick = { selectedRegion = reg },
                        label = { Text(if (reg == "ALL") "全部 (${state.nodes.size})" else reg) },
                    )
                }
            }

            Spacer(Modifier.height(10.dp))

            // 2-column rounded node grid (Reference Image 6)
            LazyVerticalGrid(
                columns = GridCells.Fixed(2),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                contentPadding = PaddingValues(bottom = 12.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(340.dp),
            ) {
                items(visibleNodes, key = { it.id }) { node ->
                    val selected = state.settings.routeMode == RouteMode.SINGLE &&
                        state.settings.activeSingleNodeId == node.id
                    Surface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onSelectSingleNode(node.id) },
                        shape = RoundedCornerShape(14.dp),
                        color = if (selected) palette.mintSingleBg else palette.surfaceElevated,
                        border = BorderStroke(
                            width = if (selected) 1.5.dp else 1.dp,
                            color = if (selected) palette.mintSingle else palette.border,
                        ),
                    ) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Text(
                                text = node.name,
                                color = palette.textPrimary,
                                fontSize = 13.sp,
                                fontWeight = FontWeight.Medium,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Spacer(Modifier.height(6.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Text(
                                    text = node.protocol.uppercase(),
                                    color = palette.textSecondary,
                                    fontSize = 11.sp,
                                )
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
                            }
                        }
                    }
                }
            }
        }
    }
}
