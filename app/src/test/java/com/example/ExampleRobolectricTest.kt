package com.example

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ExampleRobolectricTest {

  @Test
  fun `read string from context`() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val appName = context.getString(R.string.app_name)
    // The actual application name (res/values/strings.xml) — the template
    // expectation "My Application" was corrected in Phase 8.7-D.1-CORRECTION
    // when this suite first ran under the real Gradle toolchain.
    assertEquals("DevOps Agent", appName)
  }
}
