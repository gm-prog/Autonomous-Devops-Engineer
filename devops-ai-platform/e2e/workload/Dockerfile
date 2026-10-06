# E2E fixture workload: deterministic HTTP readiness for checkout-service.
FROM python:3.11-slim
WORKDIR /srv
COPY server.py /srv/server.py
RUN useradd -u 10001 -M appuser && chown -R appuser /srv
USER 10001:10001
EXPOSE 8080
CMD ["python", "/srv/server.py"]
