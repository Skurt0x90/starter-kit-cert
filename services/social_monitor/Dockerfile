FROM python:3.12-slim
WORKDIR /app
RUN useradd -r -u 10001 -s /usr/sbin/nologin app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . ./social_monitor/
ENV PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1
USER app
EXPOSE 5004
CMD ["python", "-m", "social_monitor.app"]