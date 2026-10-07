import redis
import os

class RedisDeploymentLogStore:
    """Uses redis lists to store extremely fast, append-only console traces for terminal streams."""
    def __init__(self):
        host = os.getenv("REDIS_HOST", "redis")
        port = int(os.getenv("REDIS_PORT", 6379))
        self.r = redis.Redis(host=host, port=port, db=0)

    def append_log_line(self, run_id: str, line: str):
        key = f"deploy_logs:{run_id}"
        self.r.rpush(key, line)
        self.r.expire(key, 86400) # Expire log list after 24h

    def get_logs(self, run_id: str) -> list:
        key = f"deploy_logs:{run_id}"
        decoded = [line.decode("utf-8") for line in self.r.lrange(key, 0, -1)]
        return decoded
