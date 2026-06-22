package com.example

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.material3.TabRowDefaults.tabIndicatorOffset
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.data.DeploymentLogEntity
import com.example.data.GeminiClient
import com.example.data.IncidentEntity
import com.example.data.RepoEntity
import com.example.ui.DevOpsViewModel
import com.example.ui.theme.MyApplicationTheme
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.input.pointer.pointerInput

// --- Styling Palette Constants ---
val ColorDarkBg = Color(0xFF090A10)
val ColorCardBg = Color(0xFF131622)
val ColorNeonBlue = Color(0xFF00D2FF)
val ColorNeonGreen = Color(0xFF00FF87)
val ColorNeonPurple = Color(0xFF9E00FF)
val ColorNeonPink = Color(0xFFFF007A)
val ColorMutedGray = Color(0xFF7E849A)
val ColorLightGray = Color(0xFFE2E4E9)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            MyApplicationTheme(darkTheme = true, dynamicColor = false) {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    DevOpsAppContent(modifier = Modifier.padding(innerPadding))
                }
            }
        }
    }
}

@Composable
fun DevOpsAppContent(modifier: Modifier = Modifier, viewModel: DevOpsViewModel = viewModel()) {
    val coroutineScope = rememberCoroutineScope()
    val context = LocalContext.current

    val repos by viewModel.repositories.collectAsState()
    val incidents by viewModel.incidents.collectAsState()
    val selectedRepoId = viewModel.selectedRepoId
    val selectedIncidentId = viewModel.selectedIncidentId

    val selectedRepo = repos.find { it.id == selectedRepoId }
    val selectedIncident = incidents.find { it.id == selectedIncidentId }

    // Aggregate status for elements
    val healthyNodeCount = 4
    val totalNodeCount = 4
    val activeDeployments = repos.count { it.status == "Deploying" || it.status == "Deployed" }

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(ColorDarkBg)
    ) {
        Column(modifier = Modifier.fillMaxSize()) {
            // High-fidelity Neon Header Bar
            WebOpsHeader(
                apiKeyStatus = GeminiClient.isApiKeyPresent,
                onOpenSettings = { viewModel.isSettingsSheetOpen = true }
            )

            // Primary Screen Content Switcher with animations
            Box(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
            ) {
                AnimatedContent(
                    targetState = viewModel.activeTab,
                    transitionSpec = {
                        fadeIn(animationSpec = tween(220)) togetherWith fadeOut(animationSpec = tween(220))
                    },
                    label = "TabTransition"
                ) { targetTab ->
                    when (targetTab) {
                        0 -> DashboardScreen(
                            repos = repos,
                            incidents = incidents,
                            healthyNodeCount = healthyNodeCount,
                            totalNodeCount = totalNodeCount,
                            activeDeployments = activeDeployments,
                            onSwitchTab = { viewModel.setTab(it) },
                            viewModel = viewModel
                        )
                        1 -> RepositoryScreen(
                            repos = repos,
                            selectedRepo = selectedRepo,
                            viewModel = viewModel
                        )
                        2 -> InfrastructureScreen(
                            repo = selectedRepo
                        )
                        3 -> MonitoringScreen()
                        4 -> IncidentScreen(
                            incidents = incidents,
                            selectedIncident = selectedIncident,
                            viewModel = viewModel
                        )
                    }
                }
            }

            // Neo M3 Navigation bar with custom active pill indicator styling
            DevOpsNavigationBar(
                activeTab = viewModel.activeTab,
                onTabSelected = { viewModel.setTab(it) }
            )
        }

        // Import Repository Dialog
        if (viewModel.isImportDialogOpen) {
            ImportRepositoryDialog(
                viewModel = viewModel,
                onDismiss = { viewModel.isImportDialogOpen = false }
            )
        }

        // Connectivity and API Settings Dialog Overlay
        if (viewModel.isSettingsSheetOpen) {
            ConnectivitySettingsDialog(
                viewModel = viewModel,
                onDismiss = { viewModel.isSettingsSheetOpen = false }
            )
        }
    }
}

// --- Header Component ---
@Composable
fun WebOpsHeader(apiKeyStatus: Boolean, onOpenSettings: () -> Unit) {
    Card(
        colors = CardDefaults.cardColors(containerColor = Color(0xFF0F111E)),
        shape = RoundedCornerShape(0.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 8.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 14.dp)
        ) {
            // Infinity logo with glowing neon blue dot
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .size(36.dp)
                    .background(ColorNeonPurple.copy(alpha = 0.2f), shape = CircleShape)
                    .border(1.dp, ColorNeonPurple.copy(alpha = 0.6f), shape = CircleShape)
            ) {
                Icon(
                    imageVector = Icons.Default.Refresh,
                    contentDescription = "Loop Logo",
                    tint = ColorNeonBlue,
                    modifier = Modifier.size(20.dp)
                )
            }

            Spacer(modifier = Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "DEVOPS.AI",
                    style = TextStyle(
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        fontSize = 18.sp,
                        letterSpacing = 2.sp,
                        color = Color.White
                    )
                )
                Text(
                    text = "Autonomous Multi-Agent Cluster",
                    style = TextStyle(
                        fontFamily = FontFamily.SansSerif,
                        fontWeight = FontWeight.Medium,
                        fontSize = 11.sp,
                        color = ColorNeonBlue
                    )
                )
            }

            // Live status tag
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = if (apiKeyStatus) ColorNeonGreen.copy(alpha = 0.15f) else ColorNeonPink.copy(alpha = 0.15f)
                ),
                shape = RoundedCornerShape(6.dp),
                border = BorderStroke(1.dp, if (apiKeyStatus) ColorNeonGreen.copy(alpha = 0.4f) else ColorNeonPink.copy(alpha = 0.4f)),
                modifier = Modifier.padding(start = 8.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(6.dp)
                            .background(if (apiKeyStatus) ColorNeonGreen else ColorNeonPink, shape = CircleShape)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = if (apiKeyStatus) "GEMINI_LIVE" else "PROTOTYPE_SIM",
                        style = TextStyle(
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold,
                            fontSize = 10.sp,
                            color = if (apiKeyStatus) ColorNeonGreen else ColorNeonPink
                        )
                    )
                }
            }

            Spacer(modifier = Modifier.width(8.dp))

            // Settings Config trigger icon
            IconButton(onClick = onOpenSettings, modifier = Modifier.size(28.dp)) {
                Icon(
                    imageVector = Icons.Default.Settings,
                    contentDescription = "Settings",
                    tint = ColorNeonPurple,
                    modifier = Modifier.size(18.dp)
                )
            }
        }
    }
}

// --- Navigation Bar ---
@Composable
fun DevOpsNavigationBar(activeTab: Int, onTabSelected: (Int) -> Unit) {
    NavigationBar(
        containerColor = Color(0xFF0C0E18),
        tonalElevation = 10.dp,
        modifier = Modifier.windowInsetsPadding(WindowInsets.navigationBars)
    ) {
        val items = listOf(
            NavigationItemData("Hub", Icons.Default.Home, 0),
            NavigationItemData("Repos", Icons.Default.Build, 1),
            NavigationItemData("Topology", Icons.Default.Share, 2),
            NavigationItemData("Monitor", Icons.Default.List, 3),
            NavigationItemData("Incidents", Icons.Default.Warning, 4)
        )

        items.forEach { item ->
            val selected = activeTab == item.index
            NavigationBarItem(
                selected = selected,
                onClick = { onTabSelected(item.index) },
                icon = {
                    Icon(
                        imageVector = item.icon,
                        contentDescription = item.label,
                        tint = if (selected) ColorNeonBlue else ColorMutedGray
                    )
                },
                label = {
                    Text(
                        text = item.label,
                        color = if (selected) Color.White else ColorMutedGray,
                        fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
                        fontSize = 11.sp
                    )
                },
                colors = NavigationBarItemDefaults.colors(
                    indicatorColor = ColorNeonBlue.copy(alpha = 0.15f)
                )
            )
        }
    }
}

data class NavigationItemData(val label: String, val icon: ImageVector, val index: Int)

// --- TAB 0: DASHBOARD SCREEN ---
@Composable
fun DashboardScreen(
    repos: List<RepoEntity>,
    incidents: List<IncidentEntity>,
    healthyNodeCount: Int,
    totalNodeCount: Int,
    activeDeployments: Int,
    onSwitchTab: (Int) -> Unit,
    viewModel: DevOpsViewModel
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
        contentPadding = PaddingValues(top = 16.dp, bottom = 24.dp)
    ) {
        // Hero visual banner
        item {
            Card(
                shape = RoundedCornerShape(12.dp),
                border = BorderStroke(1.dp, ColorNeonBlue.copy(alpha = 0.3f)),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(150.dp)
            ) {
                Box(modifier = Modifier.fillMaxSize()) {
                    Image(
                        painter = painterResource(id = R.drawable.img_hero_banner_custom),
                        contentDescription = "Holographic DevOps Core",
                        contentScale = ContentScale.Crop,
                        modifier = Modifier.fillMaxSize()
                    )
                    // Ambient overlay gradient
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .background(
                                Brush.verticalGradient(
                                    colors = listOf(Color.Transparent, ColorDarkBg.copy(alpha = 0.85f))
                                )
                            )
                        )
                    // Realtime health and tag overlay
                    Row(
                        modifier = Modifier
                            .align(Alignment.TopEnd)
                            .padding(12.dp)
                    ) {
                        Card(
                            colors = CardDefaults.cardColors(containerColor = ColorNeonGreen.copy(alpha = 0.2f)),
                            border = BorderStroke(1.dp, ColorNeonGreen),
                            shape = CircleShape
                        ) {
                            Text(
                                text = "ACTIVE_CLUSTER_OK",
                                color = ColorNeonGreen,
                                fontWeight = FontWeight.Bold,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 10.sp,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                            )
                        }
                    }

                    Column(
                        modifier = Modifier
                            .align(Alignment.BottomStart)
                            .padding(16.dp)
                    ) {
                        Text(
                            text = "Virtual Operator Station",
                            color = Color.White,
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = "AWS High-Availability AWS Node US-East-1 Cluster",
                            color = ColorNeonBlue,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Medium
                        )
                    }
                }
            }
        }

        // Live stats numerical matrix cards
        item {
            Row(
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                DashboardMetricCard(
                    title = "System Health",
                    value = "100%",
                    accent = ColorNeonGreen,
                    subtext = "4 Nodes Active",
                    modifier = Modifier.weight(1f)
                )
                DashboardMetricCard(
                    title = "Active Agents",
                    value = "5 Idle",
                    accent = ColorNeonBlue,
                    subtext = "Continuous Scans",
                    modifier = Modifier.weight(1f)
                )
                DashboardMetricCard(
                    title = "Incident Feed",
                    value = incidents.count { it.status == "Investigating" || it.status == "RootCauseFound" }.toString(),
                    accent = if (incidents.any { it.severity == "Critical" }) ColorNeonPink else ColorNeonPurple,
                    subtext = "Requires Review",
                    modifier = Modifier.weight(1f)
                )
            }
        }

        // Realtime moving canvas wave (HTTP transactions visualization)
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = ColorCardBg),
                shape = RoundedCornerShape(12.dp),
                border = BorderStroke(0.5.dp, ColorNeonBlue.copy(alpha = 0.2f))
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = "Network Health Monitor (Aggregated Transactions)",
                            color = Color.White,
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 13.sp,
                            modifier = Modifier.weight(1f)
                        )
                        Text(
                            text = "Live Stream",
                            fontFamily = FontFamily.Monospace,
                            fontSize = 10.sp,
                            color = ColorNeonBlue
                        )
                    }

                    Spacer(modifier = Modifier.height(16.dp))

                    // Heartbeat Canvas Wave
                    LiveMetricsChart(ColorNeonBlue)

                    Spacer(modifier = Modifier.height(8.dp))

                    Row(
                        horizontalArrangement = Arrangement.SpaceBetween,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Latency: 34ms", color = ColorMutedGray, fontSize = 11.sp)
                        Text("Load average: 0.18", color = ColorMutedGray, fontSize = 11.sp)
                        Text("ScyllaDB: Stable", color = ColorMutedGray, fontSize = 11.sp)
                    }
                }
            }
        }

        // Available Agents Showcase & Gemini Cockpit Integration
        item {
            SwarmStateMachineMonitor(viewModel = viewModel)
        }

        item {
            GeminiApiCockpit(viewModel = viewModel)
        }
    }
}

data class AgentMonitorData(val name: String, val description: String, val active: Boolean, val accent: Color)

@Composable
fun DashboardMetricCard(
    title: String,
    value: String,
    accent: Color,
    subtext: String,
    modifier: Modifier = Modifier
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = ColorCardBg),
        shape = RoundedCornerShape(10.dp),
        border = BorderStroke(0.5.dp, accent.copy(alpha = 0.2f)),
        modifier = modifier
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = title,
                color = ColorMutedGray,
                fontSize = 11.sp,
                fontWeight = FontWeight.Medium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = value,
                color = accent,
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = subtext,
                color = Color.White.copy(alpha = 0.6f),
                fontSize = 10.sp,
                maxLines = 1
            )
        }
    }
}

@Composable
fun LiveMetricsChart(color: Color) {
    // Canvas wave animation
    val transition = rememberInfiniteTransition(label = "wave")
    val phase by transition.animateFloat(
        initialValue = 0f,
        targetValue = 2f * Math.PI.toFloat(),
        animationSpec = infiniteRepeatable(
            animation = tween(1500, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "phase"
    )

    Canvas(
        modifier = Modifier
            .fillMaxWidth()
            .height(50.dp)
    ) {
        val width = size.width
        val height = size.height
        val points = mutableListOf<Offset>()

        // Generate coordinates
        for (x in 0..width.toInt() step 5) {
            val relativeX = x.toFloat() / width
            // Layering two sine waves to simulate server traffic metrics realistically!
            val sineVal1 = Math.sin(relativeX * 4 * Math.PI + phase).toFloat()
            val sineVal2 = Math.cos(relativeX * 8 * Math.PI - phase).toFloat() * 0.4f
            val y = (height / 2) + ((sineVal1 + sineVal2) * (height / 3))
            points.add(Offset(x.toFloat(), y))
        }

        // Draw path
        val path = Path().apply {
            if (points.isNotEmpty()) {
                moveTo(points[0].x, points[0].y)
                for (i in 1 until points.size) {
                    lineTo(points[i].x, points[i].y)
                }
            }
        }

        drawPath(
            path = path,
            color = color,
            style = Stroke(width = 2.dp.toPx(), cap = StrokeCap.Round)
        )
    }
}


// --- TAB 1: REPOSITORIES SCREEN ---
@Composable
fun RepositoryScreen(
    repos: List<RepoEntity>,
    selectedRepo: RepoEntity?,
    viewModel: DevOpsViewModel
) {
    val coroutineScope = rememberCoroutineScope()
    val terminalListState = rememberLazyListState()
    val logs by viewModel.selectedRepoLogs.collectAsState()

    // Automatically follow terminal outputs
    LaunchedEffect(logs.size) {
        if (logs.isNotEmpty()) {
            terminalListState.animateScrollToItem(logs.size - 1)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(
                text = "Repository Pipelines",
                style = TextStyle(color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold),
                modifier = Modifier.weight(1f)
            )

            // Import pipeline button
            Button(
                onClick = { viewModel.isImportDialogOpen = true },
                colors = ButtonDefaults.buttonColors(containerColor = ColorNeonPurple),
                shape = RoundedCornerShape(8.dp),
                contentPadding = PaddingValues(horizontal = 14.dp, vertical = 6.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.Add,
                    contentDescription = "Add",
                    tint = Color.White,
                    modifier = Modifier.size(16.dp)
                )
                Spacer(modifier = Modifier.width(4.dp))
                Text("Import Repo", fontSize = 12.sp, fontWeight = FontWeight.Bold)
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // Repository selection row (horizontal scroll cards)
        LazyRow(
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            items(repos) { repo ->
                val isSelected = selectedRepo?.id == repo.id
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = if (isSelected) ColorNeonBlue.copy(alpha = 0.15f) else ColorCardBg
                    ),
                    border = BorderStroke(
                        1.dp,
                        if (isSelected) ColorNeonBlue else Color.White.copy(alpha = 0.05f)
                    ),
                    modifier = Modifier
                        .width(170.dp)
                        .clickable { viewModel.selectRepo(repo.id) }
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                text = repo.name,
                                color = Color.White,
                                fontWeight = FontWeight.Bold,
                                fontSize = 13.sp,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                                modifier = Modifier.weight(1f)
                            )
                            if (repo.isCustom) {
                                Card(
                                    colors = CardDefaults.cardColors(containerColor = ColorNeonPurple.copy(alpha = 0.2f)),
                                    shape = RoundedCornerShape(4.dp)
                                ) {
                                    Text(
                                        "CUSTOM",
                                        color = ColorNeonPurple,
                                        fontSize = 8.sp,
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp)
                                    )
                                }
                            }
                        }

                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = repo.framework,
                            color = ColorMutedGray,
                            fontSize = 11.sp,
                            maxLines = 1
                        )
                        Spacer(modifier = Modifier.height(10.dp))

                        // Status pill tag matches repository state
                        val stateColor = when (repo.status) {
                            "Deploying" -> ColorNeonPurple
                            "Deployed" -> ColorNeonGreen
                            "Analyzing" -> ColorNeonBlue
                            "Failed" -> ColorNeonPink
                            else -> ColorMutedGray
                        }

                        Card(
                            colors = CardDefaults.cardColors(containerColor = stateColor.copy(alpha = 0.12f)),
                            shape = RoundedCornerShape(5.dp),
                            border = BorderStroke(0.5.dp, stateColor.copy(alpha = 0.6f))
                        ) {
                            Text(
                                text = repo.status.uppercase(),
                                color = stateColor,
                                fontWeight = FontWeight.Bold,
                                fontSize = 9.sp,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                            )
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        if (selectedRepo == null) {
            // Empty State
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        imageVector = Icons.Default.Info,
                        contentDescription = "Empty",
                        tint = ColorMutedGray,
                        modifier = Modifier.size(48.dp)
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        text = "No Repository Selected",
                        color = Color.White,
                        fontWeight = FontWeight.Bold,
                        fontSize = 15.sp
                    )
                    Text(
                        text = "Select or import a repository to trigger AI automation.",
                        color = ColorMutedGray,
                        fontSize = 12.sp,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(horizontal = 32.dp)
                    )
                }
            }
        } else {
            // Repo pipeline detail layout (scrollable Column containing Terminal logs + Gemini Report)
            Column(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
            ) {
                Card(
                    colors = CardDefaults.cardColors(containerColor = ColorCardBg),
                    shape = RoundedCornerShape(12.dp),
                    border = BorderStroke(0.5.dp, Color.White.copy(alpha = 0.08f)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = "Repository Information",
                            color = Color.White,
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp
                        )
                        Spacer(modifier = Modifier.height(10.dp))
                        InfoGridRow("Target Link", selectedRepo.url)
                        InfoGridRow("Tech Stack", selectedRepo.technology)
                        InfoGridRow("Framework", selectedRepo.framework)

                        Spacer(modifier = Modifier.height(16.dp))

                        // Actions Panel: Trigger Gemini Live analysis or Simulation
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            // Run analysis
                            Button(
                                onClick = { viewModel.startAnalysis(selectedRepo.id) },
                                enabled = !viewModel.isAnalyzing && !viewModel.isDeploying,
                                colors = ButtonDefaults.buttonColors(containerColor = ColorNeonBlue),
                                shape = RoundedCornerShape(6.dp),
                                modifier = Modifier.weight(1f)
                            ) {
                                if (viewModel.isAnalyzing) {
                                    CircularProgressIndicator(color = Color.White, modifier = Modifier.size(16.dp))
                                } else {
                                    Icon(Icons.Default.Refresh, contentDescription = "AI", tint = Color.White, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text("Analyze (AI)")
                                }
                            }

                            // Run deploy command
                            Button(
                                onClick = { viewModel.startDeployment(selectedRepo.id) },
                                enabled = !viewModel.isAnalyzing && !viewModel.isDeploying && selectedRepo.status != "Analyzing",
                                colors = ButtonDefaults.buttonColors(containerColor = ColorNeonGreen),
                                shape = RoundedCornerShape(6.dp),
                                modifier = Modifier.weight(1.2f)
                            ) {
                                if (viewModel.isDeploying) {
                                    CircularProgressIndicator(color = ColorDarkBg, modifier = Modifier.size(16.dp))
                                } else {
                                    Icon(Icons.Default.PlayArrow, contentDescription = "Deploy", tint = ColorDarkBg, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text("Deploy Repo", color = ColorDarkBg)
                                }
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Gemini Discovery & Analysis Report Box
                if (selectedRepo.lastAnalysisReport.isNotEmpty()) {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = ColorNeonPurple.copy(alpha = 0.05f)),
                        shape = RoundedCornerShape(12.dp),
                        border = BorderStroke(0.5.dp, ColorNeonPurple.copy(alpha = 0.3f)),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(
                                    imageVector = Icons.Default.Info,
                                    contentDescription = "AI Report",
                                    tint = ColorNeonPurple,
                                    modifier = Modifier.size(18.dp)
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = "Gemini Agent Discovery Report",
                                    color = Color.White,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 13.sp
                                )
                            }
                            Spacer(modifier = Modifier.height(10.dp))
                            Text(
                                text = selectedRepo.lastAnalysisReport,
                                color = ColorLightGray,
                                fontSize = 12.sp,
                                lineHeight = 18.sp
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Real-Time Agent Deploy Console Output Terminal (Monospace)
                if (selectedRepo.status == "Deploying" || selectedRepo.status == "Deployed" || logs.isNotEmpty()) {
                    Text(
                        text = "Deployment Terminal Channel",
                        color = Color.White,
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp
                    )
                    Spacer(modifier = Modifier.height(8.dp))

                    Card(
                        colors = CardDefaults.cardColors(containerColor = Color.Black),
                        shape = RoundedCornerShape(8.dp),
                        border = BorderStroke(1.dp, ColorNeonGreen.copy(alpha = 0.2f)),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(280.dp)
                    ) {
                        Box(modifier = Modifier.padding(12.dp)) {
                            LazyColumn(
                                state = terminalListState,
                                modifier = Modifier.fillMaxSize(),
                                verticalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
                                items(logs) { log ->
                                    val textColor = if (log.isHeader) ColorNeonGreen else ColorNeonBlue.copy(alpha = 0.8f)
                                    val weight = if (log.isHeader) FontWeight.Bold else FontWeight.Normal
                                    Text(
                                        text = log.logText,
                                        color = textColor,
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 11.sp,
                                        fontWeight = weight,
                                        lineHeight = 16.sp
                                    )
                                }
                            }

                            if (viewModel.isDeploying) {
                                Card(
                                    colors = CardDefaults.cardColors(containerColor = ColorNeonPurple.copy(alpha = 0.15f)),
                                    modifier = Modifier
                                        .align(Alignment.BottomEnd)
                                        .padding(4.dp)
                                ) {
                                    Text(
                                        text = "RUNNING_AGENTS...",
                                        color = ColorNeonPurple,
                                        fontFamily = FontFamily.Monospace,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 10.sp,
                                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun InfoGridRow(label: String, valText: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 5.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = label,
            color = ColorMutedGray,
            fontSize = 12.sp,
            fontWeight = FontWeight.Medium,
            modifier = Modifier.width(90.dp)
        )
        Text(
            text = valText,
            color = Color.White,
            fontSize = 12.sp,
            fontFamily = FontFamily.Monospace,
            modifier = Modifier.weight(1f),
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}


// --- TAB 2: INFRASTRUCTURE / BLUEPRINTS CODE VIEW SCREEN ---
@Composable
fun InfrastructureScreen(repo: RepoEntity?) {
    var activeTabIdx by remember { mutableStateOf(0) }
    val clipboard = LocalClipboardManager.current
    val coroutineScope = rememberCoroutineScope()
    var alertCopied by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Text(
            text = "Infrastructure Architecture Blueprint",
            style = TextStyle(color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold)
        )
        Text(
            text = "Inspect IaC models and topology boundaries.",
            color = ColorMutedGray,
            fontSize = 11.sp
        )

        Spacer(modifier = Modifier.height(14.dp))

        if (repo == null || repo.dockerfile.isEmpty()) {
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier.fillMaxSize()
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        imageVector = Icons.Default.Share,
                        contentDescription = "Lock",
                        tint = ColorMutedGray,
                        modifier = Modifier.size(48.dp)
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        text = "No Generation Data Loaded",
                        color = Color.White,
                        fontWeight = FontWeight.Bold,
                        fontSize = 15.sp
                    )
                    Text(
                        text = "Analyze a repository under \"Repos\" first to generate IaC Blueprints automatically.",
                        color = ColorMutedGray,
                        fontSize = 12.sp,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(horizontal = 32.dp)
                    )
                }
            }
        } else {
            // Interactive Network Topology representation Draw
            Card(
                colors = CardDefaults.cardColors(containerColor = ColorCardBg),
                shape = RoundedCornerShape(12.dp),
                border = BorderStroke(0.5.dp, ColorNeonPurple.copy(alpha = 0.2f)),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(140.dp)
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text(
                        text = "Auto-Discovered VPC Route Schema",
                        color = ColorNeonPurple,
                        fontWeight = FontWeight.Bold,
                        fontSize = 12.sp,
                        fontFamily = FontFamily.Monospace
                    )
                    Spacer(modifier = Modifier.height(8.dp))

                    // Simplified layout drawing
                    Box(
                        contentAlignment = Alignment.Center,
                        modifier = Modifier
                            .fillMaxWidth()
                            .weight(1f)
                    ) {
                        Canvas(modifier = Modifier.fillMaxSize()) {
                            val w = size.width
                            val h = size.height

                            // Draw three nodes
                            val nodeRadius = 14.dp.toPx()

                            val posS3 = Offset(w * 0.15f, h * 0.5f)
                            val posVPC = Offset(w * 0.5f, h * 0.5f)
                            val posK8s = Offset(w * 0.85f, h * 0.5f)

                            // Connectors
                            drawLine(
                                color = ColorNeonPurple.copy(alpha = 0.6f),
                                start = posS3,
                                end = posVPC,
                                strokeWidth = 2.dp.toPx()
                            )
                            drawLine(
                                color = ColorNeonBlue.copy(alpha = 0.6f),
                                start = posVPC,
                                end = posK8s,
                                strokeWidth = 2.dp.toPx()
                            )

                            // Nodes
                            drawCircle(color = ColorNeonPurple, radius = nodeRadius, center = posS3)
                            drawCircle(color = ColorCardBg, radius = nodeRadius - 2.dp.toPx(), center = posS3)

                            drawCircle(color = ColorNeonBlue, radius = nodeRadius, center = posVPC)
                            drawCircle(color = ColorCardBg, radius = nodeRadius - 2.dp.toPx(), center = posVPC)

                            drawCircle(color = ColorNeonGreen, radius = nodeRadius, center = posK8s)
                            drawCircle(color = ColorCardBg, radius = nodeRadius - 2.dp.toPx(), center = posK8s)
                        }

                        // Labels superimposed
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceAround
                        ) {
                            Text("AWS Gateway", color = Color.White, fontFamily = FontFamily.Monospace, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                            Text("ECS / VPC Zone", color = Color.White, fontFamily = FontFamily.Monospace, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                            Text("Replica Pods", color = Color.White, fontFamily = FontFamily.Monospace, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Blueprints code selection tabs
            val tabs = listOf("Dockerfile", "Kubernetes", "AWS Terraform", "CI/CD Pipeline")
            ScrollableTabRow(
                selectedTabIndex = activeTabIdx,
                containerColor = Color.Transparent,
                edgePadding = 0.dp,
                indicator = { tabPositions ->
                    TabRowDefaults.SecondaryIndicator(
                        modifier = Modifier.tabIndicatorOffset(tabPositions[activeTabIdx]),
                        color = ColorNeonPurple
                    )
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                tabs.forEachIndexed { idx, title ->
                    Tab(
                        selected = activeTabIdx == idx,
                        onClick = { activeTabIdx = idx },
                        text = {
                            Text(
                                text = title,
                                fontSize = 12.sp,
                                fontWeight = if (activeTabIdx == idx) FontWeight.Bold else FontWeight.Normal,
                                color = if (activeTabIdx == idx) Color.White else ColorMutedGray
                            )
                        }
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Code viewer card
            val codeToDisplay = when (activeTabIdx) {
                0 -> repo.dockerfile
                1 -> repo.k8sYaml
                2 -> repo.terraformTf
                else -> repo.pipelineYaml
            }

            Card(
                colors = CardDefaults.cardColors(containerColor = Color(0xFF07080E)),
                shape = RoundedCornerShape(8.dp),
                border = BorderStroke(0.5.dp, Color.White.copy(alpha = 0.08f)),
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "CODE_SOURCE (${tabs[activeTabIdx].uppercase()})",
                            color = ColorMutedGray,
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold,
                            fontSize = 11.sp,
                            modifier = Modifier.weight(1f)
                        )

                        // Copy action with animation alert
                        IconButton(
                            onClick = {
                                clipboard.setText(AnnotatedString(codeToDisplay))
                                coroutineScope.launch {
                                    alertCopied = true
                                    delay(1500)
                                    alertCopied = false
                                }
                            },
                            modifier = Modifier.size(24.dp)
                        ) {
                            Icon(
                                imageVector = if (alertCopied) Icons.Default.CheckCircle else Icons.Default.Share,
                                contentDescription = "Copy",
                                tint = if (alertCopied) ColorNeonGreen else ColorNeonBlue,
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    // Code Viewer Pane
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .fillMaxWidth()
                            .verticalScroll(rememberScrollState())
                            .horizontalScroll(rememberScrollState())
                    ) {
                        Text(
                            text = codeToDisplay,
                            style = TextStyle(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp,
                                color = ColorLightGray,
                                lineHeight = 16.sp
                            )
                        )
                    }
                }
            }
        }
    }
}


// --- TAB 3: MONITORING SCREEN (THE METRIC OBSERVER COCKPIT) ---
@Composable
fun MonitoringScreen() {
    var isAlert1Active by remember { mutableStateOf(true) }
    var isAlert2Active by remember { mutableStateOf(false) }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
        contentPadding = PaddingValues(bottom = 24.dp)
    ) {
        item {
            Text(
                text = "Prometheus Cluster Telemetry",
                style = TextStyle(color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold)
            )
            Text(
                text = "Realtime scraping configurations and service health streams.",
                color = ColorMutedGray,
                fontSize = 11.sp
            )
        }

        // Live Visual Gauges
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                GaugeCard("Node CPU Core Usage", "24.5%", 0.245f, ColorNeonBlue, modifier = Modifier.weight(1f))
                GaugeCard("Memory Allocation", "68.2%", 0.682f, ColorNeonPurple, modifier = Modifier.weight(1f))
            }
        }

        // Realtime logs aggregator terminal
        item {
            Text(
                text = "Aggregated Cluster Logs (Loki Stream)",
                color = Color.White,
                fontWeight = FontWeight.Bold,
                fontSize = 13.sp
            )
            Spacer(modifier = Modifier.height(8.dp))

            val logsList = listOf(
                "11:51:24 spring-gateway [INFO] Routing request GET /api/v1/auth/session to node 10.0.1.25",
                "11:51:25 catalog-service [INFO] Database pool utilization: Active 12 / Max 100",
                "11:51:28 spring-gateway [WARN] Connection duration limit warning: Connection checking latency reached 840ms",
                "11:51:30 spring-gateway [INFO] Auto-Scaler checked: Average node CPU 24%. No scaling required.",
                "11:51:32 auth-service [INFO] Token decrypted correctly context user_id=9825",
                "11:51:35 gateway-service [DEBUG] Scrape target endpoint hit from address 10.0.1.45"
            )

            Card(
                colors = CardDefaults.cardColors(containerColor = Color.Black),
                border = BorderStroke(0.5.dp, Color.White.copy(alpha = 0.1f)),
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(180.dp)
            ) {
                LazyColumn(
                    modifier = Modifier.padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    items(logsList) { log ->
                        val color = when {
                            log.contains("[INFO]") -> ColorNeonBlue
                            log.contains("[WARN]") -> ColorNeonPink
                            else -> ColorLightGray
                        }
                        Text(
                            text = log,
                            color = color,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 10.sp,
                            lineHeight = 14.sp
                        )
                    }
                }
            }
        }

        // Action Toggles for alerts
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = ColorCardBg),
                shape = RoundedCornerShape(10.dp),
                border = BorderStroke(0.5.dp, Color.White.copy(alpha = 0.08f)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "Auto-Remediation Trigger Guards",
                        color = Color.White,
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp
                    )
                    Spacer(modifier = Modifier.height(12.dp))

                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Database connection pooling leak fix alert", color = Color.White, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                            Text("Auto-Fix when utilization spikes above 95%", color = ColorMutedGray, fontSize = 10.sp)
                        }
                        Switch(
                            checked = isAlert1Active,
                            onCheckedChange = { isAlert1Active = it },
                            colors = SwitchDefaults.colors(checkedThumbColor = ColorNeonBlue, checkedTrackColor = ColorNeonBlue.copy(alpha = 0.3f))
                        )
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Kubernetes over-provisioning pod scale limits", color = Color.White, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                            Text("Auto-scale cluster size to match traffic latency thresholds", color = ColorMutedGray, fontSize = 10.sp)
                        }
                        Switch(
                            checked = isAlert2Active,
                            onCheckedChange = { isAlert2Active = it },
                            colors = SwitchDefaults.colors(checkedThumbColor = ColorNeonPurple, checkedTrackColor = ColorNeonPurple.copy(alpha = 0.3f))
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun GaugeCard(title: String, score: String, proportion: Float, accentColor: Color, modifier: Modifier = Modifier) {
    Card(
        colors = CardDefaults.cardColors(containerColor = ColorCardBg),
        shape = RoundedCornerShape(10.dp),
        border = BorderStroke(0.5.dp, accentColor.copy(alpha = 0.2f)),
        modifier = modifier
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier
                .padding(16.dp)
                .fillMaxWidth()
        ) {
            Text(title, color = ColorMutedGray, fontSize = 11.sp, fontWeight = FontWeight.Medium)
            Spacer(modifier = Modifier.height(12.dp))

            Box(contentAlignment = Alignment.Center) {
                // Drawing actual circle gauge indicators!
                Canvas(modifier = Modifier.size(70.dp)) {
                    drawArc(
                        color = Color.White.copy(alpha = 0.08f),
                        startAngle = 135f,
                        sweepAngle = 270f,
                        useCenter = false,
                        style = Stroke(width = 6.dp.toPx(), cap = StrokeCap.Round)
                    )
                    drawArc(
                        color = accentColor,
                        startAngle = 135f,
                        sweepAngle = 270f * proportion,
                        useCenter = false,
                        style = Stroke(width = 6.dp.toPx(), cap = StrokeCap.Round)
                    )
                }
                Text(score, color = Color.White, fontSize = 16.sp, fontWeight = FontWeight.Bold)
            }
        }
    }
}


// --- TAB 4: INCIDENT CENTER RESPONSE PAGE ---
@Composable
fun IncidentScreen(
    incidents: List<IncidentEntity>,
    selectedIncident: IncidentEntity?,
    viewModel: DevOpsViewModel
) {
    val logsListState = rememberLazyListState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Text(
            text = "Virtual Incident Command Center",
            style = TextStyle(color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold)
        )
        Text(
            text = "AI Multi-Agent Automated RCA and Configuration Repair.",
            color = ColorMutedGray,
            fontSize = 11.sp
        )

        Spacer(modifier = Modifier.height(14.dp))

        // Horizontal incidents stream list cards
        LazyRow(
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            items(incidents) { ticket ->
                val isSelected = selectedIncident?.id == ticket.id
                val severityColor = when (ticket.severity) {
                    "Critical" -> ColorNeonPink
                    "High" -> ColorNeonPurple
                    else -> ColorNeonBlue
                }

                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = if (isSelected) ColorNeonPink.copy(alpha = 0.08f) else ColorCardBg
                    ),
                    border = BorderStroke(
                        1.dp,
                        if (isSelected) ColorNeonPink else Color.White.copy(alpha = 0.05f)
                    ),
                    modifier = Modifier
                        .width(180.dp)
                        .clickable { viewModel.selectIncident(ticket.id) }
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(6.dp)
                                    .background(severityColor, shape = CircleShape)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                "SEV-" + ticket.severity.uppercase(),
                                color = severityColor,
                                fontWeight = FontWeight.Bold,
                                fontSize = 10.sp
                            )
                        }

                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = ticket.title,
                            color = Color.White,
                            fontWeight = FontWeight.Bold,
                            fontSize = 12.sp,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Spacer(modifier = Modifier.height(10.dp))

                        // Status Tag indicating Repair Level
                        val statusCol = if (ticket.status == "Fixed") ColorNeonGreen else ColorNeonBlue
                        Card(
                            colors = CardDefaults.cardColors(containerColor = statusCol.copy(alpha = 0.12f)),
                            shape = RoundedCornerShape(4.dp)
                        ) {
                            Text(
                                text = ticket.status.uppercase(),
                                color = statusCol,
                                fontWeight = FontWeight.Bold,
                                fontSize = 9.sp,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                            )
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        if (selectedIncident == null) {
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        imageVector = Icons.Default.Warning,
                        contentDescription = "Empty",
                        tint = ColorMutedGray,
                        modifier = Modifier.size(48.dp)
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        text = "No Incident Selected",
                        color = Color.White,
                        fontWeight = FontWeight.Bold,
                        fontSize = 15.sp
                    )
                    Text(
                        text = "Choose an active incident or ticket above to begin automated Root Cause Analysis and remediation repair.",
                        color = ColorMutedGray,
                        fontSize = 12.sp,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(horizontal = 32.dp)
                    )
                }
            }
        } else {
            // Live Interactive Troubleshooting pane
            Column(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
            ) {
                Card(
                    colors = CardDefaults.cardColors(containerColor = ColorCardBg),
                    shape = RoundedCornerShape(12.dp),
                    border = BorderStroke(0.5.dp, Color.White.copy(alpha = 0.08f))
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = selectedIncident.title,
                            color = Color.White,
                            fontWeight = FontWeight.Bold,
                            fontSize = 15.sp
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = selectedIncident.description,
                            color = ColorLightGray,
                            fontSize = 12.sp,
                            lineHeight = 18.sp
                        )
                        Spacer(modifier = Modifier.height(14.dp))

                        InfoGridRow("Target App", selectedIncident.serviceName)
                        InfoGridRow("Ticket Severity", selectedIncident.severity)

                        Spacer(modifier = Modifier.height(16.dp))

                        // Investigation Trigger Row Buttons
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            Button(
                                onClick = { viewModel.startInvestigation(selectedIncident.id) },
                                enabled = !viewModel.isInvestigating && !viewModel.isAutoFixing && selectedIncident.status != "Fixed",
                                colors = ButtonDefaults.buttonColors(containerColor = ColorNeonBlue),
                                modifier = Modifier.weight(1f),
                                shape = RoundedCornerShape(6.dp)
                            ) {
                                if (viewModel.isInvestigating) {
                                    CircularProgressIndicator(color = Color.White, modifier = Modifier.size(16.dp))
                                } else {
                                    Text("Analyze Logs")
                                }
                            }

                            Button(
                                onClick = { /* Guides to swipe */ },
                                enabled = false,
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = Color.White.copy(alpha = 0.04f),
                                    disabledContainerColor = Color.White.copy(alpha = 0.04f)
                                ),
                                modifier = Modifier.weight(1f),
                                shape = RoundedCornerShape(6.dp)
                            ) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.Lock,
                                        contentDescription = "Bypass-Protection Lock",
                                        tint = if (selectedIncident.status == "RootCauseFound") ColorNeonPink else ColorMutedGray,
                                        modifier = Modifier.size(14.dp)
                                    )
                                    Text(
                                        text = if (selectedIncident.status == "RootCauseFound") "Locked: Swipe Below" else "Auto-Fix Pending",
                                        color = if (selectedIncident.status == "RootCauseFound") ColorNeonPink else ColorMutedGray,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 11.sp
                                    )
                                }
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Root cause analysis output text
                if (selectedIncident.rootCause.isNotEmpty()) {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = ColorNeonBlue.copy(alpha = 0.06f)),
                        shape = RoundedCornerShape(12.dp),
                        border = BorderStroke(1.dp, ColorNeonBlue.copy(alpha = 0.4f)),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text(
                                text = "Root Cause Discovery Summary",
                                color = ColorNeonBlue,
                                fontWeight = FontWeight.Bold,
                                fontSize = 13.sp,
                                fontFamily = FontFamily.Monospace
                            )
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = selectedIncident.rootCause,
                                color = Color.White,
                                fontSize = 12.sp,
                                lineHeight = 18.sp
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                // Proposed remediation code fix block
                if (selectedIncident.remediationPlan.isNotEmpty()) {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = ColorNeonGreen.copy(alpha = 0.06f)),
                        shape = RoundedCornerShape(12.dp),
                        border = BorderStroke(1.dp, ColorNeonGreen.copy(alpha = 0.4f)),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text(
                                text = "Loki Agent Remediation",
                                color = ColorNeonGreen,
                                fontWeight = FontWeight.Bold,
                                fontSize = 13.sp,
                                fontFamily = FontFamily.Monospace
                            )
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = selectedIncident.remediationPlan,
                                color = Color.White,
                                fontSize = 12.sp,
                                lineHeight = 18.sp
                            )
                        }
                    }
                }

                // HUMAN IN THE LOOP INTEGRATION GATEWAY
                if (selectedIncident.status == "RootCauseFound") {
                    Spacer(modifier = Modifier.height(16.dp))
                    HumanInTheLoopAuthorizationView(viewModel = viewModel, incident = selectedIncident)
                }

                Spacer(modifier = Modifier.height(14.dp))

                // Investigator Console Logs Output Monospace panel
                if (selectedIncident.agentLog.isNotEmpty() || viewModel.isInvestigating) {
                    Text(
                        text = "Automated AI Agent Actions",
                        color = Color.White,
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp
                    )
                    Spacer(modifier = Modifier.height(8.dp))

                    Card(
                        colors = CardDefaults.cardColors(containerColor = Color.Black),
                        shape = RoundedCornerShape(8.dp),
                        border = BorderStroke(1.dp, ColorNeonBlue.copy(alpha = 0.3f)),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(200.dp)
                    ) {
                        Box(modifier = Modifier.padding(12.dp)) {
                            LazyColumn(
                                state = logsListState,
                                modifier = Modifier.fillMaxSize()
                            ) {
                                item {
                                    Text(
                                        text = selectedIncident.agentLog,
                                        color = ColorNeonBlue,
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 11.sp,
                                        lineHeight = 16.sp
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}


// --- REPO IMPORT DIALOG COMPONENT ---
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ImportRepositoryDialog(
    viewModel: DevOpsViewModel,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            Button(
                onClick = { viewModel.importRepository() },
                colors = ButtonDefaults.buttonColors(containerColor = ColorNeonPurple),
                shape = RoundedCornerShape(6.dp)
            ) {
                Text("Provision Setup", fontWeight = FontWeight.Bold)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Abort", color = ColorMutedGray)
            }
        },
        title = {
            Text(
                "Import Repository Profile",
                color = Color.White,
                fontWeight = FontWeight.Bold,
                fontSize = 16.sp
            )
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    "Register code parameters to compile live blueprints via Gemini AI.",
                    color = ColorMutedGray,
                    fontSize = 11.sp
                )

                OutlinedTextField(
                    value = viewModel.newRepoName,
                    onValueChange = { viewModel.newRepoName = it },
                    label = { Text("Repo Name (e.g. My-FastAPI)") },
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = Color.White,
                        unfocusedTextColor = ColorLightGray,
                        focusedBorderColor = ColorNeonPurple,
                        unfocusedBorderColor = ColorMutedGray
                    ),
                    maxLines = 1,
                    modifier = Modifier.fillMaxWidth()
                )

                OutlinedTextField(
                    value = viewModel.newRepoUrl,
                    onValueChange = { viewModel.newRepoUrl = it },
                    label = { Text("Repository GitHub URL or Description") },
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = Color.White,
                        unfocusedTextColor = ColorLightGray,
                        focusedBorderColor = ColorNeonPurple,
                        unfocusedBorderColor = ColorMutedGray
                    ),
                    maxLines = 1,
                    modifier = Modifier.fillMaxWidth()
                )

                OutlinedTextField(
                    value = viewModel.newRepoFramework,
                    onValueChange = { viewModel.newRepoFramework = it },
                    label = { Text("Framework (e.g. Next.js 14)") },
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = Color.White,
                        unfocusedTextColor = ColorLightGray,
                        focusedBorderColor = ColorNeonPurple,
                        unfocusedBorderColor = ColorMutedGray
                    ),
                    maxLines = 1,
                    modifier = Modifier.fillMaxWidth()
                )

                OutlinedTextField(
                    value = viewModel.newRepoTech,
                    onValueChange = { viewModel.newRepoTech = it },
                    label = { Text("Main Tech Description") },
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = Color.White,
                        unfocusedTextColor = ColorLightGray,
                        focusedBorderColor = ColorNeonPurple,
                        unfocusedBorderColor = ColorMutedGray
                    ),
                    maxLines = 1,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        containerColor = ColorCardBg,
        shape = RoundedCornerShape(12.dp)
    )
}

// --- GATEWAY CONNECTIVITY AND API SETTINGS DIALOG ---
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConnectivitySettingsDialog(
    viewModel: DevOpsViewModel,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            Button(
                onClick = onDismiss,
                colors = ButtonDefaults.buttonColors(containerColor = ColorNeonPurple),
                shape = RoundedCornerShape(6.dp)
            ) {
                Text("Apply & Close", fontWeight = FontWeight.Bold)
            }
        },
        title = {
            Text(
                "Connectivity Settings",
                color = Color.White,
                fontWeight = FontWeight.Bold,
                fontSize = 16.sp,
                fontFamily = FontFamily.SansSerif
            )
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                Text(
                    text = "Configure the active execution bridge to route multi-agent deployments, alerts, and code reviews directly to your remote server architecture.",
                    color = ColorMutedGray,
                    fontSize = 11.sp,
                    lineHeight = 16.sp
                )

                // Remote API Toggle
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(Color.White.copy(alpha = 0.03f), RoundedCornerShape(8.dp))
                        .padding(horizontal = 12.dp, vertical = 8.dp)
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            "Connect to Remote Backend",
                            color = Color.White,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            "Queries active API services instead of simulated presets.",
                            color = ColorMutedGray,
                            fontSize = 10.sp
                        )
                    }
                    Switch(
                        checked = viewModel.isRemoteGatewayEnabled,
                        onCheckedChange = { viewModel.setRemoteGateway(it) },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = ColorNeonBlue,
                            checkedTrackColor = ColorNeonBlue.copy(alpha = 0.3f)
                        )
                    )
                }

                if (viewModel.isRemoteGatewayEnabled) {
                    // API Endpoint Input Card
                    OutlinedTextField(
                        value = viewModel.apiUrlGateway,
                        onValueChange = { viewModel.updateApiUrl(it) },
                        label = { Text("Base Gateway Endpoint URL") },
                        placeholder = { Text("e.g. http://10.0.2.2:8000") },
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = Color.White,
                            unfocusedTextColor = ColorLightGray,
                            focusedBorderColor = ColorNeonBlue,
                            unfocusedBorderColor = ColorMutedGray
                        ),
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )

                    // Connection Testing Dashboard
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Button(
                            onClick = { viewModel.testBackendConnection() },
                            enabled = !viewModel.isCheckingConnection,
                            colors = ButtonDefaults.buttonColors(containerColor = ColorNeonBlue.copy(alpha = 0.15f)),
                            border = BorderStroke(1.dp, ColorNeonBlue.copy(alpha = 0.6f)),
                            shape = RoundedCornerShape(6.dp),
                            modifier = Modifier.weight(1f)
                        ) {
                            if (viewModel.isCheckingConnection) {
                                CircularProgressIndicator(color = ColorNeonBlue, modifier = Modifier.size(14.dp), strokeWidth = 2.dp)
                            } else {
                                Text("Ping Endpoint", color = ColorNeonBlue, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                            }
                        }

                        // Connection Status Pill
                        val (text, color) = when (viewModel.connectionStatus) {
                            "ONLINE" -> "CONNECTED" to ColorNeonGreen
                            "OFFLINE" -> "UNREACHABLE" to ColorNeonPink
                            "CHECKING" -> "PINGING..." to ColorNeonPurple
                            else -> "UNCHECKED" to ColorMutedGray
                        }

                        Card(
                            colors = CardDefaults.cardColors(containerColor = color.copy(alpha = 0.12f)),
                            border = BorderStroke(1.dp, color.copy(alpha = 0.4f)),
                            shape = RoundedCornerShape(4.dp),
                            modifier = Modifier.height(36.dp)
                        ) {
                            Box(contentAlignment = Alignment.Center, modifier = Modifier.fillMaxHeight().padding(horizontal = 12.dp)) {
                                Text(
                                    text = text,
                                    color = color,
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 10.sp
                                )
                            }
                        }
                    }

                    Card(
                        colors = CardDefaults.cardColors(containerColor = Color.Black.copy(alpha = 0.3f)),
                        border = BorderStroke(0.5.dp, Color.White.copy(alpha = 0.05f)),
                        shape = RoundedCornerShape(6.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(10.dp)) {
                            Text(
                                "✔ Set to http://10.0.2.2:8000 for standard localhost inside Android Emulators.",
                                color = ColorMutedGray,
                                fontSize = 9.sp,
                                fontFamily = FontFamily.Monospace
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                "✔ Deploy live to Vercel or Render and enter the secure https URL to fetch live states.",
                                color = ColorMutedGray,
                                fontSize = 9.sp,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                    }
                }
            }
        },
        containerColor = ColorCardBg,
        shape = RoundedCornerShape(12.dp)
    )
}

// --- CORE FEATURE UPGRADE: LIVE CHASSIS & EXPERT SYSTEM MODELS ---

data class SwarmAgent(
    val name: String,
    val initial: String,
    val specialty: String,
    val task: String,
    val status: String,
    val color: Color
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SwarmStateMachineMonitor(
    viewModel: DevOpsViewModel,
    modifier: Modifier = Modifier
) {
    val swarmAgents = listOf(
        SwarmAgent("Repo-Expert", "RE", "Workspace Parsing & Semantic Search", "Analyzing Git branches & frameworks...", "SCANNING", ColorNeonBlue),
        SwarmAgent("IaC-Builder", "IB", "Infrastructure as Code Synthesis", "Writing and matching VPC / subnet modules...", "COMPILING", ColorNeonPurple),
        SwarmAgent("Audit-Inspector", "AI", "Vulnerability & IAM Compliance", "Scanning security endpoints & port boundaries...", "INSPECTING", ColorNeonGreen),
        SwarmAgent("Hotfix-Validator", "HV", "Chaos Testing & Active Validation", "Executing docker container test scripts...", "VERIFYING", ColorNeonPink)
    )

    var autoCycle by remember { mutableStateOf(true) }

    // Automated cycling of active agents
    if (autoCycle) {
        LaunchedEffect(Unit) {
            while (autoCycle) {
                delay(3000)
                viewModel.selectedAgentIndex = (viewModel.selectedAgentIndex + 1) % 4
            }
        }
    }

    val activeAgent = swarmAgents[viewModel.selectedAgentIndex]

    Card(
        colors = CardDefaults.cardColors(containerColor = ColorCardBg),
        shape = RoundedCornerShape(12.dp),
        border = BorderStroke(0.5.dp, ColorNeonBlue.copy(alpha = 0.2f)),
        modifier = modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            // Header Row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = "Swarm State Machine Monitor",
                        color = Color.White,
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp
                    )
                    Text(
                        text = "Realtime virtual multi-agent orchestration",
                        color = ColorMutedGray,
                        fontSize = 11.sp
                    )
                }
                
                // Pulsing Active Badge
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(6.dp)
                            .background(ColorNeonGreen, shape = CircleShape)
                    )
                    Text(
                        text = "SWARM_ACTIVE",
                        color = ColorNeonGreen,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        fontSize = 9.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Graph and Details Split Layout
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(180.dp),
                horizontalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // Left interactive graph canvas
                Box(
                    modifier = Modifier
                        .size(150.dp)
                        .background(Color.Black.copy(alpha = 0.2f), RoundedCornerShape(8.dp))
                        .border(1.dp, Color.White.copy(alpha = 0.03f), RoundedCornerShape(8.dp)),
                    contentAlignment = Alignment.Center
                ) {
                    // Connective Network Lines Background Canvas
                    Canvas(modifier = Modifier.fillMaxSize()) {
                        val w = size.width
                        val h = size.height
                        val strokeColor = Color.White.copy(alpha = 0.1f)
                        val pathEffect = PathEffect.dashPathEffect(floatArrayOf(10f, 10f), 0f)

                        // Outer cross
                        drawLine(color = strokeColor, start = Offset(w * 0.25f, h * 0.25f), end = Offset(w * 0.75f, h * 0.25f), strokeWidth = 1.dp.toPx(), pathEffect = pathEffect)
                        drawLine(color = strokeColor, start = Offset(w * 0.75f, h * 0.25f), end = Offset(w * 0.75f, h * 0.75f), strokeWidth = 1.dp.toPx(), pathEffect = pathEffect)
                        drawLine(color = strokeColor, start = Offset(w * 0.75f, h * 0.75f), end = Offset(w * 0.25f, h * 0.75f), strokeWidth = 1.dp.toPx(), pathEffect = pathEffect)
                        drawLine(color = strokeColor, start = Offset(w * 0.25f, h * 0.75f), end = Offset(w * 0.25f, h * 0.25f), strokeWidth = 1.dp.toPx(), pathEffect = pathEffect)
                        
                        // Diagonal crossing
                        drawLine(color = strokeColor, start = Offset(w * 0.25f, h * 0.25f), end = Offset(w * 0.75f, h * 0.75f), strokeWidth = 1.dp.toPx(), pathEffect = pathEffect)
                        drawLine(color = strokeColor, start = Offset(w * 0.75f, h * 0.25f), end = Offset(w * 0.25f, h * 0.75f), strokeWidth = 1.dp.toPx(), pathEffect = pathEffect)
                    }

                    // 4 Interactive Nodes placed in Box boundaries
                    val coords = listOf(
                        Alignment.TopStart,
                        Alignment.TopEnd,
                        Alignment.BottomStart,
                        Alignment.BottomEnd
                    )

                    swarmAgents.forEachIndexed { idx, agent ->
                        val isSelected = viewModel.selectedAgentIndex == idx
                        val transition = rememberInfiniteTransition(label = "ripple")
                        
                        // Glowing ripple radius animation
                        val rippleScale by transition.animateFloat(
                            initialValue = 0.8f,
                            targetValue = 1.8f,
                            animationSpec = infiniteRepeatable(
                                animation = tween(1400, easing = LinearEasing),
                                repeatMode = RepeatMode.Restart
                            ),
                            label = "scale"
                        )
                        val rippleAlpha by transition.animateFloat(
                            initialValue = 0.5f,
                            targetValue = 0f,
                            animationSpec = infiniteRepeatable(
                                animation = tween(1400, easing = LinearEasing),
                                repeatMode = RepeatMode.Restart
                            ),
                            label = "alpha"
                        )

                        Box(
                            modifier = Modifier
                                .align(coords[idx])
                                .padding(8.dp)
                                .size(36.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            // Pulsing Ripple Outer Container
                            if (isSelected) {
                                Box(
                                    modifier = Modifier
                                        .fillMaxSize()
                                        .drawBehind {
                                            drawCircle(
                                                color = agent.color.copy(alpha = rippleAlpha),
                                                radius = (size.minDimension / 1.8f) * rippleScale
                                            )
                                        }
                                )
                            }

                            // Interactive Circle Badge Node
                            Box(
                                contentAlignment = Alignment.Center,
                                modifier = Modifier
                                    .fillMaxSize()
                                    .background(
                                        if (isSelected) agent.color else Color.White.copy(alpha = 0.05f),
                                        shape = CircleShape
                                    )
                                    .border(
                                        1.dp,
                                        if (isSelected) Color.White else agent.color.copy(alpha = 0.6f),
                                        shape = CircleShape
                                    )
                                    .clickable {
                                        viewModel.selectedAgentIndex = idx
                                        autoCycle = false // Halt autocycle on user interaction
                                    }
                            ) {
                                Text(
                                    text = agent.initial,
                                    color = if (isSelected) ColorDarkBg else Color.White,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 11.sp,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                        }
                    }
                }

                // Right: Details Panel
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxHeight()
                        .background(Color.Black.copy(alpha = 0.15f), RoundedCornerShape(8.dp))
                        .padding(10.dp),
                    verticalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(6.dp)
                                    .background(activeAgent.color, shape = CircleShape)
                            )
                            Text(
                                text = activeAgent.name.uppercase(),
                                color = activeAgent.color,
                                fontWeight = FontWeight.Bold,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp
                            )
                        }

                        Text(
                            text = activeAgent.specialty,
                            color = Color.White,
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 11.sp
                        )

                        Text(
                            text = activeAgent.task,
                            color = ColorMutedGray,
                            fontSize = 10.sp,
                            lineHeight = 14.sp,
                            minLines = 2,
                            maxLines = 3,
                            overflow = TextOverflow.Ellipsis
                        )
                    }

                    // Bottom Action Panel in Details Card
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Card(
                            colors = CardDefaults.cardColors(containerColor = activeAgent.color.copy(alpha = 0.12f)),
                            shape = RoundedCornerShape(4.dp)
                        ) {
                            Text(
                                text = activeAgent.status,
                                color = activeAgent.color,
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                fontSize = 8.sp,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                            )
                        }

                        // Cycle switch button pill
                        Box(
                            modifier = Modifier
                                .background(if (autoCycle) ColorNeonBlue.copy(alpha = 0.12f) else Color.White.copy(alpha = 0.04f), RoundedCornerShape(4.dp))
                                .border(0.5.dp, if (autoCycle) ColorNeonBlue else ColorMutedGray.copy(alpha = 0.3f), RoundedCornerShape(4.dp))
                                .clickable { autoCycle = !autoCycle }
                                .padding(horizontal = 6.dp, vertical = 2.dp)
                        ) {
                            Text(
                                text = if (autoCycle) "LOOP: ON" else "LOOP: OFF",
                                color = if (autoCycle) ColorNeonBlue else ColorMutedGray,
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                fontSize = 8.sp
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun GeminiApiCockpit(viewModel: DevOpsViewModel) {
    val breakerText = when (viewModel.circuitBreakerState) {
        "CLOSED" -> "CLOSED"
        "OPEN" -> "TRIPPED"
        else -> "HALF_OPEN"
    }

    val breakerCol = when (viewModel.circuitBreakerState) {
        "CLOSED" -> ColorNeonGreen
        "OPEN" -> ColorNeonPink
        else -> ColorNeonPurple
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = ColorCardBg),
        shape = RoundedCornerShape(12.dp),
        border = BorderStroke(0.5.dp, ColorNeonPurple.copy(alpha = 0.2f)),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            // Header Row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = "Gemini Resilient API Cockpit",
                        color = Color.White,
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp
                    )
                    Text(
                        text = "Realtime safety constraints & hardware budgets",
                        color = ColorMutedGray,
                        fontSize = 11.sp
                    )
                }

                // Circuit Breakers Indicator Badge

                Card(
                    colors = CardDefaults.cardColors(containerColor = breakerCol.copy(alpha = 0.15f)),
                    border = BorderStroke(1.dp, breakerCol.copy(alpha = 0.5f)),
                    shape = RoundedCornerShape(4.dp)
                ) {
                    Text(
                        text = "BREAKER: $breakerText",
                        color = breakerCol,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        fontSize = 9.sp,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(18.dp))

            // Dials row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceEvenly,
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Dial 1: Rate limits (Requests Per Minute)
                val rpmProportion = (viewModel.geminiRateLimitRPM.toFloat() / 100f).coerceIn(0f, 1f)
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Box(contentAlignment = Alignment.Center, modifier = Modifier.size(64.dp)) {
                        Canvas(modifier = Modifier.fillMaxSize()) {
                            drawArc(
                                color = Color.White.copy(alpha = 0.05f),
                                startAngle = 135f,
                                sweepAngle = 270f,
                                useCenter = false,
                                style = Stroke(width = 4.dp.toPx(), cap = StrokeCap.Round)
                            )
                            drawArc(
                                color = ColorNeonBlue,
                                startAngle = 135f,
                                sweepAngle = 270f * rpmProportion,
                                useCenter = false,
                                style = Stroke(width = 4.dp.toPx(), cap = StrokeCap.Round)
                            )
                        }
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Text(
                                "${viewModel.geminiRateLimitRPM}",
                                color = Color.White,
                                fontWeight = FontWeight.Bold,
                                fontSize = 12.sp,
                                fontFamily = FontFamily.Monospace
                            )
                            Text(
                                "RPM",
                                color = ColorNeonBlue,
                                fontWeight = FontWeight.Bold,
                                fontSize = 8.sp
                            )
                        }
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                    Text("API Rate Load", color = ColorMutedGray, fontSize = 10.sp)
                }

                // Dial 2: Cost metrics (USD Charges accumulated)
                val costProportion = (viewModel.geminiTokenCharges.toFloat() / 5.0f).coerceIn(0f, 1f)
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Box(contentAlignment = Alignment.Center, modifier = Modifier.size(64.dp)) {
                        Canvas(modifier = Modifier.fillMaxSize()) {
                            drawArc(
                                color = Color.White.copy(alpha = 0.05f),
                                startAngle = 135f,
                                sweepAngle = 270f,
                                useCenter = false,
                                style = Stroke(width = 4.dp.toPx(), cap = StrokeCap.Round)
                            )
                            drawArc(
                                color = ColorNeonPurple,
                                startAngle = 135f,
                                sweepAngle = 270f * costProportion,
                                useCenter = false,
                                style = Stroke(width = 4.dp.toPx(), cap = StrokeCap.Round)
                            )
                        }
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Text(
                                String.format("$%.2f", viewModel.geminiTokenCharges),
                                color = Color.White,
                                fontWeight = FontWeight.Bold,
                                fontSize = 10.sp,
                                fontFamily = FontFamily.Monospace
                            )
                            Text(
                                "USD",
                                color = ColorNeonPurple,
                                fontWeight = FontWeight.Bold,
                                fontSize = 7.sp
                            )
                        }
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                    Text("Token Cost", color = ColorMutedGray, fontSize = 10.sp)
                }

                // Dial 3: Circuit breaker visual gauge indicator
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Box(contentAlignment = Alignment.Center, modifier = Modifier.size(64.dp)) {
                        Canvas(modifier = Modifier.fillMaxSize()) {
                            drawCircle(
                                color = breakerCol.copy(alpha = 0.04f),
                                radius = size.minDimension / 2.3f
                            )
                            drawCircle(
                                color = breakerCol.copy(alpha = 0.2f),
                                radius = size.minDimension / 2.3f,
                                style = Stroke(width = 1.dp.toPx())
                            )
                        }

                        // Inner blinking ring or static triangle
                        val transition = rememberInfiniteTransition(label = "blink")
                        val blinkAlpha by transition.animateFloat(
                            initialValue = 0.2f,
                            targetValue = 1.0f,
                            animationSpec = infiniteRepeatable(
                                animation = tween(1000, easing = LinearEasing),
                                repeatMode = RepeatMode.Reverse
                            ),
                            label = "blink"
                        )
                        
                        Box(
                            modifier = Modifier
                                .size(16.dp)
                                .background(
                                    breakerCol.copy(alpha = if (viewModel.isSimulatingSpike) blinkAlpha else 0.8f),
                                    shape = CircleShape
                                )
                                .border(1.dp, Color.White.copy(alpha = 0.5f), CircleShape)
                        )
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = "BREAKER",
                        color = breakerCol,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
            }

            Spacer(modifier = Modifier.height(18.dp))

            // Action triggers for spikes and resets
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Button(
                    onClick = { viewModel.simulateLoadSpike() },
                    enabled = !viewModel.isSimulatingSpike,
                    colors = ButtonDefaults.buttonColors(containerColor = ColorNeonPurple.copy(alpha = 0.15f)),
                    border = BorderStroke(1.dp, ColorNeonPurple.copy(alpha = 0.5f)),
                    shape = RoundedCornerShape(6.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    if (viewModel.isSimulatingSpike) {
                        CircularProgressIndicator(
                            color = ColorNeonPurple,
                            modifier = Modifier.size(14.dp),
                            strokeWidth = 2.dp
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            "SPIKING REQ...",
                            color = ColorNeonPurple,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold
                        )
                    } else {
                        Text(
                            "SIMULATE LOAD SPIKE",
                            color = ColorNeonPurple,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }

                Button(
                    onClick = { viewModel.resetCircuitBreaker() },
                    colors = ButtonDefaults.buttonColors(containerColor = ColorMutedGray.copy(alpha = 0.1f)),
                    border = BorderStroke(1.dp, ColorMutedGray.copy(alpha = 0.3f)),
                    shape = RoundedCornerShape(6.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Text(
                        "RESET COCKPIT",
                        color = Color.White,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }
    }
}

@Composable
fun HumanInTheLoopAuthorizationView(
    viewModel: DevOpsViewModel,
    incident: IncidentEntity,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var swipeOffset by remember { mutableStateOf(0f) }
    
    val diffLines = when {
        incident.title.contains("Database") -> listOf(
            "// gateway/src/main/resources/application.yml",
            "@@ -12,4 +12,4 @@",
            "-  hikari:",
            "-    maximum-pool-size: 10",
            "-    connection-timeout: 1000",
            "+  hikari:",
            "+    maximum-pool-size: 250",
            "+    connection-timeout: 5000"
        )
        incident.title.contains("Unauthorized") -> listOf(
            "// terraform/modules/s3/main.tf",
            "@@ -24,3 +24,3 @@",
            "-  principal = \"*\"",
            "-  action    = \"s3:*\"",
            "+  principal = \"arn:aws:iam::123456:role/runner\"",
            "+  action    = [\"s3:GetObject\", \"s3:PutObject\"]"
        )
        else -> listOf(
            "// k8s/hpa-scaling-policy.yaml",
            "@@ -5,4 +5,5 @@",
            "-  minReplicas: 1",
            "-  maxReplicas: 1",
            "+  minReplicas: 2",
            "+  maxReplicas: 8",
            "+  targetCPUUtilizationPercentage: 75"
        )
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = ColorCardBg),
        shape = RoundedCornerShape(12.dp),
        border = BorderStroke(1.dp, ColorNeonPink.copy(alpha = 0.3f)),
        modifier = modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            // Slack-style alerting feed header
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(ColorNeonPink.copy(alpha = 0.08f), RoundedCornerShape(8.dp))
                    .padding(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Custom Warning Avatar/Indicator
                Box(
                    modifier = Modifier
                        .size(32.dp)
                        .background(ColorNeonPink.copy(alpha = 0.2f), shape = CircleShape)
                        .border(1.dp, ColorNeonPink, shape = CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Default.Warning,
                        contentDescription = "Alert",
                        tint = ColorNeonPink,
                        modifier = Modifier.size(16.dp)
                    )
                }

                Spacer(modifier = Modifier.width(12.dp))

                Column {
                    Text(
                        text = "HUMAN AUTHORIZATION GATEWAY",
                        color = ColorNeonPink,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp
                    )
                    Text(
                        text = "Deployment blocked. Operator sign-off requested to merge hotfix.",
                        color = Color.White,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 11.sp,
                        lineHeight = 14.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            Text(
                "Proposed Code Patch Diff Visualizer",
                color = Color.White,
                fontWeight = FontWeight.SemiBold,
                fontSize = 12.sp
            )
            Spacer(modifier = Modifier.height(8.dp))

            // Code terminal rendering unified Git Diff
            Card(
                colors = CardDefaults.cardColors(containerColor = Color.Black),
                border = BorderStroke(1.dp, Color.White.copy(alpha = 0.05f)),
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier
                        .padding(12.dp)
                        .horizontalScroll(rememberScrollState())
                ) {
                    diffLines.forEach { line ->
                        val (lineColor, bgCol) = when {
                            line.startsWith("-") -> ColorNeonPink to ColorNeonPink.copy(alpha = 0.08f)
                            line.startsWith("+") -> ColorNeonGreen to ColorNeonGreen.copy(alpha = 0.08f)
                            line.startsWith("@@") -> ColorNeonPurple to Color.Transparent
                            line.startsWith("//") -> ColorMutedGray to Color.Transparent
                            else -> ColorLightGray to Color.Transparent
                        }

                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(bgCol)
                                .padding(vertical = 1.dp, horizontal = 4.dp)
                        ) {
                            Text(
                                text = line,
                                color = lineColor,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 10.sp,
                                fontWeight = if (line.startsWith("-") || line.startsWith("+")) FontWeight.Bold else FontWeight.Normal
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            // Interactive swipe button
            Text(
                "Verify and Drag Slider to Deploy & Merge:",
                color = ColorLightGray,
                fontSize = 11.sp,
                fontWeight = FontWeight.Medium
            )
            Spacer(modifier = Modifier.height(10.dp))

            // Swipe track container
            BoxWithConstraints(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(54.dp)
                    .background(Color.White.copy(alpha = 0.03f), RoundedCornerShape(27.dp))
                    .border(1.dp, ColorNeonPink.copy(alpha = 0.4f), RoundedCornerShape(27.dp)),
                contentAlignment = Alignment.CenterStart
            ) {
                val density = androidx.compose.ui.platform.LocalDensity.current
                val widthPx = constraints.maxWidth.toFloat()
                val thumbWidth = 54.dp
                val thumbWidthPx = with(density) { thumbWidth.toPx() }
                val maxSwipePx = widthPx - thumbWidthPx

                // Swipe Action triggers when sliding past 85% of track
                val swipeThreshold = maxSwipePx * 0.85f

                LaunchedEffect(viewModel.isAutoFixing) {
                    if (!viewModel.isAutoFixing) {
                        swipeOffset = 0f
                    }
                }

                // Centered prompt text
                Text(
                    text = if (viewModel.isAutoFixing) "COMMITTING HOTFIX..." else "SWIPE TO AUTHORIZE & MERGE",
                    color = ColorNeonPink,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    fontSize = 11.sp,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 48.dp)
                )

                // Dragging thumb icon
                val dragXModifier = Modifier
                    .offset(x = with(density) { swipeOffset.toDp() })
                    .size(54.dp)
                    .clip(CircleShape)
                    .background(ColorNeonPink)
                    .pointerInput(Unit) {
                        if (viewModel.isAutoFixing) return@pointerInput
                        detectDragGestures(
                            onDrag = { change, dragAmount ->
                                change.consume()
                                swipeOffset = (swipeOffset + dragAmount.x).coerceIn(0f, maxSwipePx)
                            },
                            onDragEnd = {
                                if (swipeOffset >= swipeThreshold) {
                                    swipeOffset = maxSwipePx
                                    viewModel.startAutoFix(incident.id)
                                    android.widget.Toast.makeText(context, "Authorization Sign-Off Complete! Deploying...", android.widget.Toast.LENGTH_SHORT).show()
                                } else {
                                    swipeOffset = 0f
                                }
                            }
                        )
                    }

                Box(
                    modifier = dragXModifier,
                    contentAlignment = Alignment.Center
                ) {
                    if (viewModel.isAutoFixing) {
                        CircularProgressIndicator(
                            color = ColorDarkBg,
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp
                        )
                    } else {
                        Icon(
                            imageVector = Icons.Default.ArrowForward,
                            contentDescription = "Swipe Arrow",
                            tint = ColorDarkBg,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }
            }
        }
    }
}

