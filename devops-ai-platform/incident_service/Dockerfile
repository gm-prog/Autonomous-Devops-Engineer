FROM python:3.11-slim

# Package-mode runtime: build context is devops-ai-platform/, so the image
# contains the full package tree and boots with `uvicorn incident_service.main:app`.
WORKDIR /platform

COPY requirements.txt /platform/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . /platform

EXPOSE 8050

CMD ["uvicorn", "incident_service.main:app", "--host", "0.0.0.0", "--port", "8050"]
