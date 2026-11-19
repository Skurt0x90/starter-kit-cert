FROM python:3.12-slim
WORKDIR /app
RUN useradd -r -u 10001 -s /usr/sbin/nologin app
RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=app:app . ./web_watcher/
ENV PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1
USER app
EXPOSE 5002
CMD ["python", "-m", "vuln_scanner.app"]