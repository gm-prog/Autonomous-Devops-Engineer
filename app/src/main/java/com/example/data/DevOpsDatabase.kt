package com.example.data

import android.content.Context
import androidx.room.*
import kotlinx.coroutines.flow.Flow

// --- Entities ---

@Entity(tableName = "repositories")
data class RepoEntity(
    @PrimaryKey(autoGenerate = true) val id: Int = 0,
    val name: String,
    val url: String,
    val framework: String,
    val technology: String,
    val dockerfile: String = "",
    val k8sYaml: String = "",
    val terraformTf: String = "",
    val pipelineYaml: String = "",
    val status: String = "Idle", // Idle, Analyzing, Generated, Deploying, Deployed, Failed
    val lastAnalysisReport: String = "",
    val isCustom: Boolean = false,
    val timestamp: Long = System.currentTimeMillis()
)

@Entity(tableName = "incidents")
data class IncidentEntity(
    @PrimaryKey(autoGenerate = true) val id: Int = 0,
    val title: String,
    val description: String,
    val severity: String, // Low, Medium, High, Critical
    val serviceName: String,
    val status: String = "Investigating", // Investigating, RootCauseFound, Fixed
    val rootCause: String = "",
    val remediationPlan: String = "",
    val timestamp: Long = System.currentTimeMillis(),
    val agentLog: String = ""
)

@Entity(tableName = "deployment_logs")
data class DeploymentLogEntity(
    @PrimaryKey(autoGenerate = true) val id: Int = 0,
    val repoId: Int,
    val logText: String,
    val stepIndex: Int, // 1 to 11
    val isHeader: Boolean = false,
    val timestamp: Long = System.currentTimeMillis()
)

// --- DAO ---

@Dao
interface DevOpsDao {
    // Repositories
    @Query("SELECT * FROM repositories ORDER BY timestamp DESC")
    fun getAllRepositoriesFlow(): Flow<List<RepoEntity>>

    @Query("SELECT * FROM repositories WHERE id = :id")
    suspend fun getRepositoryById(id: Int): RepoEntity?

    @Query("SELECT * FROM repositories WHERE name = :name")
    suspend fun getRepositoryByName(name: String): RepoEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertRepository(repo: RepoEntity): Long

    @Update
    suspend fun updateRepository(repo: RepoEntity)

    @Delete
    suspend fun deleteRepository(repo: RepoEntity)

    @Query("DELETE FROM repositories")
    suspend fun deleteAllRepositories()

    // Incidents
    @Query("SELECT * FROM incidents ORDER BY timestamp DESC")
    fun getAllIncidentsFlow(): Flow<List<IncidentEntity>>

    @Query("SELECT * FROM incidents WHERE id = :id")
    suspend fun getIncidentById(id: Int): IncidentEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertIncident(incident: IncidentEntity): Long

    @Update
    suspend fun updateIncident(incident: IncidentEntity)

    @Query("DELETE FROM incidents WHERE id = :id")
    suspend fun deleteIncidentId(id: Int)

    // Deployment Logs
    @Query("SELECT * FROM deployment_logs WHERE repoId = :repoId ORDER BY id ASC")
    fun getLogsForRepoFlow(repoId: Int): Flow<List<DeploymentLogEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertLog(log: DeploymentLogEntity)

    @Query("DELETE FROM deployment_logs WHERE repoId = :repoId")
    suspend fun clearLogsForRepo(repoId: Int)
}

// --- Database Class ---

@Database(
    entities = [RepoEntity::class, IncidentEntity::class, DeploymentLogEntity::class],
    version = 1,
    exportSchema = false
)
abstract class DevOpsDatabase : RoomDatabase() {
    abstract fun devOpsDao(): DevOpsDao

    companion object {
        @Volatile
        private var INSTANCE: DevOpsDatabase? = null

        fun getDatabase(context: Context): DevOpsDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    DevOpsDatabase::class.java,
                    "devops_agent_db"
                ).build()
                INSTANCE = instance
                instance
            }
        }
    }
}
