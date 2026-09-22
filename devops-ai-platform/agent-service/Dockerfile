FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir fastapi>=0.100.0 uvicorn>=0.22.0 requests>=2.31.0 pydantic>=2.0.0
EXPOSE 8020
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8020"]
