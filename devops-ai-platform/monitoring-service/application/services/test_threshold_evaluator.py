import unittest

from application.services.threshold_evaluator import ThresholdEvaluator, ThresholdRule


class ThresholdEvaluatorTests(unittest.TestCase):
    def test_cpu_breach_is_detected(self):
        result = ThresholdEvaluator([
            ThresholdRule("cpu_percent", 90.0, ">=", "critical")
        ]).evaluate({"cpu_percent": 95.0})

        self.assertEqual(result["status"], "BREACHED")
        self.assertEqual(result["severity"], "critical")
        self.assertEqual(result["breach_count"], 1)

    def test_boundary_value_counts_as_breach(self):
        result = ThresholdEvaluator([
            ThresholdRule("cpu_percent", 90.0, ">=", "critical")
        ]).evaluate({"cpu_percent": 90.0})

        self.assertEqual(result["status"], "BREACHED")

    def test_multiple_breaches_keep_highest_severity(self):
        result = ThresholdEvaluator([
            ThresholdRule("cpu_percent", 90.0, ">=", "high"),
            ThresholdRule("latency_ms", 1000.0, ">=", "critical"),
        ]).evaluate({"cpu_percent": 95.0, "latency_ms": 1500.0})

        self.assertEqual(result["breach_count"], 2)
        self.assertEqual(result["severity"], "critical")

    def test_missing_metric_is_not_a_breach(self):
        result = ThresholdEvaluator([
            ThresholdRule("cpu_percent", 90.0)
        ]).evaluate({"latency_ms": 120.0})

        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["breaches"], [])

    def test_non_numeric_metric_is_ignored(self):
        result = ThresholdEvaluator([
            ThresholdRule("cpu_percent", 90.0)
        ]).evaluate({"cpu_percent": "not-a-number"})

        self.assertEqual(result["status"], "OK")

    def test_strict_operator_is_honored(self):
        evaluator = ThresholdEvaluator([
            ThresholdRule("cpu_percent", 90.0, ">", "high")
        ])

        self.assertEqual(
            evaluator.evaluate({"cpu_percent": 90.0})["status"],
            "OK",
        )
        self.assertEqual(
            evaluator.evaluate({"cpu_percent": 90.1})["status"],
            "BREACHED",
        )


if __name__ == "__main__":
    unittest.main()
