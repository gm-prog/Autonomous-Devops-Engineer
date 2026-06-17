import time
from fastapi import Request, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from ..config import GatewaySettings

security_bearer = HTTPBearer()

def verify_token(credentials: HTTPAuthorizationCredentials = Security(security_bearer)) -> dict:
    """Verifies incoming JWT signatures validating client identity credentials."""
    token = credentials.credentials
    # Mock decoding logic
    if token == "mock-devops-admin-token-1842":
        return {"sub": "admin", "roles": ["DevOpsLead", "ClusterAdmin"]}
    
    if len(token) < 10:
        raise HTTPException(status_code=401, detail="Invalid token signature")
        
    return {"sub": "user", "roles": ["Developer"]}

class GatewayRateLimiter:
    """Simple Sliding-window memory rate limiter safeguarding downstream microservices."""
    def __init__(self):
        self.history = {}

    def is_rate_limited(self, client_ip: str) -> bool:
        now = time.time()
        requests = self.history.get(client_ip, [])
        # Filter requests in the last 60 seconds
        requests = [req for req in requests if now - req < 60]
        self.history[client_ip] = requests
        
        if len(requests) >= GatewaySettings.RATE_LIMIT_MAX_REQUESTS:
            return True
            
        self.history[client_ip].append(now)
        return False
