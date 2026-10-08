package com.example

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/**
 * Phase 8.7-D.1-CORRECTION: the analysis-source badge must never render an
 * unknown or absent state as a live/success color.
 *
 * This is a pure-JVM test of the extracted [analysisBadgeColor] mapping —
 * deterministic and golden-free. It replaces the template's
 * `GreetingScreenshotTest` (which referenced a `Greeting` composable that
 * does not exist in this application and so could never compile) and an
 * intermediate roborazzi screenshot attempt (fragile: it needs a committed
 * pixel-exact golden that cannot be reliably produced outside CI, and a
 * bare `captureRoboImage` in verify mode fails when no golden exists).
 *
 * The invariant under test is the real intent of the `MainActivity` badge
 * fix: **only `LIVE_BACKEND` (a genuine authenticated server-side success)
 * may render the live/success color; every other value — including unknown
 * and absent states — renders a safe, non-success color.**
 */
class AnalysisBadgeColorTest {

  @Test
  fun live_backend_renders_the_success_color() {
    assertEquals(ColorNeonGreen, analysisBadgeColor("LIVE_BACKEND"))
  }

  @Test
  fun offline_sim_renders_the_safe_offline_color() {
    assertEquals(ColorNeonBlue, analysisBadgeColor("OFFLINE_SIM"))
  }

  @Test
  fun failure_states_render_the_failure_color() {
    assertEquals(ColorNeonPink, analysisBadgeColor("LIVE_FAILED"))
    assertEquals(ColorNeonPink, analysisBadgeColor("OFFLINE_FAILED"))
  }

  @Test
  fun unknown_and_absent_states_never_render_the_success_color() {
    // The core safety invariant: an unrecognized state must never be shown
    // as a live success.
    val unknowns = listOf(
      "",          // absent
      "UNKNOWN",
      "live_backend", // wrong case
      "LIVE_backend", // wrong case
      "LIVE_BACKEND ", // trailing whitespace
      " LIVE_BACKEND", // leading whitespace
      "null",
      "garbage",
      "LIVE_BACKEND_EXTRA",
    )
    for (mode in unknowns) {
      assertNotEquals(
        "state '$mode' must never render the live/success color",
        ColorNeonGreen,
        analysisBadgeColor(mode)
      )
    }
  }

  @Test
  fun unknown_and_absent_states_fall_back_to_the_safe_offline_color() {
    assertEquals(ColorNeonBlue, analysisBadgeColor("some-future-state"))
    assertEquals(ColorNeonBlue, analysisBadgeColor(""))
  }
}
