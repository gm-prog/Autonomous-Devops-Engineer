FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Repository directory uses a hyphen; copy it into a valid Python package name.
COPY agent-service /app/agent_service

ENV PYTHONUNBUFFERED=1
EXPOSE 8020

CMD ["uvicorn", "agent_service.main:app", "--host", "0.0.0.0", "--port", "8020"]
