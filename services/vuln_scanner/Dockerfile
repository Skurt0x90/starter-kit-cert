FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . ./vuln_scanner/
ENV PYTHONPATH=/app
EXPOSE 5002
CMD ["python", "-m", "vuln_scanner.app"]