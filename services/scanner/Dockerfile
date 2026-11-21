FROM python:3.12-slim

WORKDIR /app

COPY services/scanner/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY services/scanner/ /app/services/scanner/
COPY content/ /app/content/

WORKDIR /app/services/scanner

CMD ["python", "-m", "scanner.worker"]
