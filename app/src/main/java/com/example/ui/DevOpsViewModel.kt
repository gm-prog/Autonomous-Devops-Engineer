package com.example.ui

import android.app.Application
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.data.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class DevOpsViewModel(application: Application) : AndroidViewModel(application) {

    private val repository: DevOpsRepository
    val repositories: StateFlow<List<RepoEntity>>
    val incidents: StateFlow<List<IncidentEntity>>

    // Form inputs for importing repository
    var newRepoName by mutableStateOf("")
    var newRepoUrl by mutableStateOf("")
    var newRepoFramework by mutableStateOf("FastAPI")
    var newRepoTech by mutableStateOf("Python 3.12 / FastAPI Rest")
    var isImportDialogOpen by mutableStateOf(false)

    // Selection states
    var activeTab by mutableStateOf(0) // 0: Dashboard, 1: Repositories, 2: Infrastructure, 3: Monitoring, 4: Incidents
    var selectedRepoId by mutableStateOf<Int?>(null)
    var selectedIncidentId by mutableStateOf<Int?>(null)

    // Async actions progress tracker
    var isAnalyzing by mutableStateOf(false)
    var isDeploying by mutableStateOf(false)
    var isInvestigating by mutableStateOf(false)
    var isAutoFixing by mutableStateOf(false)

    // Api Gateway persistence & connection testing states
    private val prefs = application.getSharedPreferences("devops_api_prefs", android.content.Context.MODE_PRIVATE)
    
    var isRemoteGatewayEnabled by mutableStateOf(prefs.getBoolean("is_remote_gateway_enabled", false))
        private set
    
    var apiUrlGateway by mutableStateOf(prefs.getString("api_url_gateway", "http://10.0.2.2:8000") ?: "http://10.0.2.2:8000")
        private set

    var connectionStatus by mutableStateOf("UNCHECKED") // UNCHECKED, ONLINE, OFFLINE
    var isCheckingConnection by mutableStateOf(false)
    var isSettingsSheetOpen by mutableStateOf(false)

    fun setRemoteGateway(enabled: Boolean) {
        isRemoteGatewayEnabled = enabled
        prefs.edit().putBoolean("is_remote_gateway_enabled", enabled).apply()
        connectionStatus = "UNCHECKED"
    }

    fun updateApiUrl(newUrl: String) {
        apiUrlGateway = newUrl
        prefs.edit().putString("api_url_gateway", newUrl).apply()
        connectionStatus = "UNCHECKED"
    }

    fun testBackendConnection() {
        viewModelScope.launch {
            isCheckingConnection = true
            connectionStatus = "CHECKING"
            val success = BackendGatewayClient.testConnection(apiUrlGateway)
            connectionStatus = if (success) "ONLINE" else "OFFLINE"
            isCheckingConnection = false
        }
    }

    init {
        val database = DevOpsDatabase.getDatabase(application)
        val dao = database.devOpsDao()
        repository = DevOpsRepository(dao)

        repositories = repository.allRepositories
            .stateIn(
                scope = viewModelScope,
                started = SharingStarted.WhileSubscribed(5000),
                initialValue = emptyList()
            )

        incidents = repository.allIncidents
            .stateIn(
                scope = viewModelScope,
                started = SharingStarted.WhileSubscribed(5000),
                initialValue = emptyList()
            )

        // Prepopulate presets
        viewModelScope.launch {
            repository.setupPresetsIfEmpty()
            // Default select the first repo if available
            val repos = repositories.value
            if (repos.isNotEmpty() && selectedRepoId == null) {
                selectedRepoId = repos.first().id
            }
        }
    }

    // Selected Repo State
    val selectedRepoFlow: Flow<RepoEntity?> = MutableStateFlow<RepoEntity?>(null) // Placeholder representation
    
    // Logs for selected deployment
    private val selectedRepoIdFlow = MutableStateFlow<Int>(-1)
    
    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    val selectedRepoLogs: StateFlow<List<DeploymentLogEntity>> = selectedRepoIdFlow
        .flatMapLatest { repoId ->
            if (repoId != -1) {
                repository.getLogsForRepo(repoId)
            } else {
                kotlinx.coroutines.flow.flowOf(emptyList())
            }
        }
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = emptyList()
        )

    fun selectRepo(id: Int) {
        selectedRepoId = id
        selectedRepoIdFlow.value = id
    }

    fun selectIncident(id: Int) {
        selectedIncidentId = id
    }

    fun setTab(index: Int) {
        activeTab = index
    }

    fun importRepository() {
        if (newRepoName.isEmpty() || newRepoUrl.isEmpty()) return
        viewModelScope.launch {
            val newRepo = RepoEntity(
                name = newRepoName,
                url = newRepoUrl,
                framework = newRepoFramework,
                technology = newRepoTech,
                status = "Idle",
                isCustom = true
            )
            val generatedId = repository.insertRepo(newRepo)
            selectRepo(generatedId.toInt())
            isImportDialogOpen = false
            // Reset form
            newRepoName = ""
            newRepoUrl = ""
            newRepoFramework = "FastAPI"
            newRepoTech = "Python 3.12 / FastAPI Rest"
            
            // Auto prompt visualizer
            activeTab = 1
        }
    }

    fun deleteRepository(repo: RepoEntity) {
        viewModelScope.launch {
            repository.deleteRepo(repo)
            if (selectedRepoId == repo.id) {
                selectedRepoId = null
                selectedRepoIdFlow.value = -1
            }
        }
    }

    fun startAnalysis(repoId: Int) {
        viewModelScope.launch {
            isAnalyzing = true
            repository.analyzeRepoAsync(
                repoId = repoId,
                isRemote = isRemoteGatewayEnabled,
                remoteUrl = apiUrlGateway
            )
            isAnalyzing = false
        }
    }

    fun startDeployment(repoId: Int) {
        viewModelScope.launch {
            isDeploying = true
            repository.runDeploymentWorkflow(repoId)
            isDeploying = false
        }
    }

    fun startInvestigation(incidentId: Int) {
        viewModelScope.launch {
            isInvestigating = true
            repository.investigateIncident(incidentId)
            isInvestigating = false
        }
    }

    fun startAutoFix(incidentId: Int) {
        viewModelScope.launch {
            isAutoFixing = true
            repository.applyAutoFix(incidentId)
            isAutoFixing = false
        }
    }
}
