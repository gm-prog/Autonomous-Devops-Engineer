package com.example

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.example.data.DevOpsDatabase
import com.example.data.DevOpsRepository
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Regression test for the preset-duplication bug:
 * `setupPresetsIfEmpty()` previously used a predicate helper that always
 * returned null, so the 3 preset repos + 2 preset incidents were
 * re-inserted on every app launch (unbounded growth).
 *
 * Seeds twice (simulating two cold starts) and asserts the preset data
 * is present exactly once.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class DevOpsRepositorySeedingTest {

    @Test
    fun `seeding is idempotent - presets inserted exactly once`() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val db = Room.inMemoryDatabaseBuilder(context, DevOpsDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        val repository = DevOpsRepository(db.devOpsDao())

        // Simulate two consecutive app cold starts
        repository.setupPresetsIfEmpty()
        repository.setupPresetsIfEmpty()

        val repos = db.devOpsDao().getAllRepositoriesFlow().first()
        val incidents = db.devOpsDao().getAllIncidentsFlow().first()

        assertEquals(3, repos.size)
        assertEquals(2, incidents.size)
        assertEquals(
            setOf("Flask Microservice", "Spring Gatekeeper", "NextJS Dashboard"),
            repos.map { it.name }.toSet()
        )
        db.close()
    }

    @Test
    fun `seeding is skipped when user data already exists`() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val db = Room.inMemoryDatabaseBuilder(context, DevOpsDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        val dao = db.devOpsDao()
        val repository = DevOpsRepository(dao)

        // User imports a repo first, then the app "re-seeds"
        dao.insertRepository(
            com.example.data.RepoEntity(
                name = "My Custom Repo",
                url = "github.com/me/repo",
                framework = "FastAPI",
                technology = "Python 3.12",
                isCustom = true
            )
        )
        repository.setupPresetsIfEmpty()

        val repos = dao.getAllRepositoriesFlow().first()
        // Only the user's repo - presets must NOT be injected into a used DB
        assertEquals(1, repos.size)
        assertEquals("My Custom Repo", repos.first().name)
        db.close()
    }
}
