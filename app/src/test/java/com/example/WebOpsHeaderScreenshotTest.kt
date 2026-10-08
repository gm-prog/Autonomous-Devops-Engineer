package com.example

import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onRoot
import com.example.WebOpsHeader
import com.example.ui.theme.MyApplicationTheme
import com.github.takahirom.roborazzi.captureRoboImage
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Screenshot regression for the analysis-source badge in the app header.
 *
 * The original template test (`GreetingScreenshotTest`) referenced a
 * `Greeting` composable that does not exist in this application, so the
 * unit-test sources could never compile under the real Gradle toolchain.
 * Phase 8.7-D.1-CORRECTION re-targets the test at `WebOpsHeader` — an
 * existing, dependency-free composable — so the roborazzi/Robolectric
 * screenshot pipeline runs for real and additionally guards the
 * OFFLINE_SIM badge rendering (unknown states must never render the
 * live/success color).
 *
 * The theme is fixed (light, no dynamic color) so the capture is
 * deterministic across runners. Golden image: committed on the first run
 * that captures it (roborazzi records when no golden exists and asserts
 * against it afterwards).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class WebOpsHeaderScreenshotTest {

  @get:Rule val composeTestRule = createComposeRule()

  @Test
  fun offline_sim_header_screenshot() {
    composeTestRule.setContent {
      MyApplicationTheme(darkTheme = false, dynamicColor = false) {
        WebOpsHeader(analysisMode = "OFFLINE_SIM", onOpenSettings = {})
      }
    }

    composeTestRule.onRoot().captureRoboImage(
      filePath = "src/test/screenshots/webops_header_offline_sim.png"
    )
  }
}
