import io
import json
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from infrastructure.prometheus.scraper_client import (
    PrometheusScraperClient,
    PrometheusScraperError,
)


def response(body: object, status: int = 200):
    payload = json.dumps(body).encode("utf-8")

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def getcode(self):
            return status

        @property
        def status(self):
            return status

        def read(self):
            return payload

    return FakeResponse()


class PrometheusScraperClientTests(unittest.TestCase):
    def setUp(self):
        self.client = PrometheusScraperClient(
            endpoint="http://prometheus:9090/",
            timeout_seconds=3.0,
        )

    @patch("infrastructure.prometheus.scraper_client.urlopen")
    def test_query_returns_successful_prometheus_payload(self, mock_urlopen):
        payload = {
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [{"metric": {"job": "api"}, "value": [1, "42.5"]}],
            },
        }
        mock_urlopen.return_value = response(payload)

        result = self.client.query_instant_metric('up{job="api"}')

        self.assertEqual(result, payload)
        request = mock_urlopen.call_args.args[0]
        self.assertIn("/api/v1/query?", request.full_url)
        self.assertIn("query=up%7Bjob%3D%22api%22%7D", request.full_url)
        self.assertEqual(mock_urlopen.call_args.kwargs["timeout"], 3.0)

    @patch("infrastructure.prometheus.scraper_client.urlopen")
    def test_http_error_is_normalized(self, mock_urlopen):
        mock_urlopen.side_effect = HTTPError(
            "http://prometheus:9090/api/v1/query",
            503,
            "unavailable",
            {},
            io.BytesIO(b""),
        )

        with self.assertRaises(PrometheusScraperError):
            self.client.query_instant_metric("up")

    @patch("infrastructure.prometheus.scraper_client.urlopen")
    def test_connection_error_is_normalized(self, mock_urlopen):
        mock_urlopen.side_effect = URLError("connection refused")

        with self.assertRaises(PrometheusScraperError):
            self.client.query_instant_metric("up")

    @patch("infrastructure.prometheus.scraper_client.urlopen")
    def test_invalid_json_is_rejected(self, mock_urlopen):
        class InvalidJsonResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def read(self):
                return b"not-json"

        mock_urlopen.return_value = InvalidJsonResponse()

        with self.assertRaises(PrometheusScraperError):
            self.client.query_instant_metric("up")

    @patch("infrastructure.prometheus.scraper_client.urlopen")
    def test_prometheus_api_error_is_rejected(self, mock_urlopen):
        mock_urlopen.return_value = response(
            {
                "status": "error",
                "errorType": "bad_data",
                "error": "invalid parameter query",
            }
        )

        with self.assertRaises(PrometheusScraperError) as ctx:
            self.client.query_instant_metric("up[")

        self.assertIn("bad_data", str(ctx.exception))
        self.assertIn("invalid parameter query", str(ctx.exception))

    def test_empty_query_is_rejected_before_network_call(self):
        with self.assertRaises(ValueError):
            self.client.query_instant_metric("  ")

    def test_endpoint_without_scheme_is_supported(self):
        client = PrometheusScraperClient(endpoint="prometheus:9090")
        self.assertEqual(client._normalize_endpoint(client.endpoint), "http://prometheus:9090")


if __name__ == "__main__":
    unittest.main()
