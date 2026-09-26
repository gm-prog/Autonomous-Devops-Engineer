import unittest
from unittest.mock import Mock, patch
from fastapi.testclient import TestClient
from api_gateway.main import app
from api_gateway.core.auth import mint_token

class GatewayTests(unittest.TestCase):
    def test_jwt_wrong_secret_rejected(self):
        from api_gateway.core.auth import decode_and_verify
        token=mint_token("user",secret="correct")
        with self.assertRaises(ValueError): decode_and_verify(token,"wrong")

    def test_jwt_expired_rejected(self):
        from api_gateway.core.auth import decode_and_verify
        token=mint_token("user",secret="correct",ttl_seconds=-1)
        with self.assertRaises(ValueError): decode_and_verify(token,"correct")

    @patch("api_gateway.routers.gateway_router.requests.post")
    def test_dispatch_is_real_forward(self, post):
        post.return_value=Mock(status_code=200,json=lambda:{"ok":True})
        from api_gateway.core.auth import GatewaySettings
        with patch.object(GatewaySettings,"JWT_SECRET","test-secret"):
            token=mint_token("user",secret="test-secret")
            r=TestClient(app).post("/v1/gateway/dispatch/repo",json={"x":1},headers={"Authorization":f"Bearer {token}"})
        self.assertEqual(r.status_code,200)
        self.assertEqual(r.json()["status"],"FORWARDED")
        post.assert_called_once()

if __name__=="__main__": unittest.main()
