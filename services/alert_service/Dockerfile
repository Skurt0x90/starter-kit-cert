FROM python:3.12-slim
WORKDIR /app
RUN useradd -r -u 10001 -s /usr/sbin/nologin app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=app:app . ./web_watcher/
ENV PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1
USER app
EXPOSE 5005
CMD ["gunicorn", "-w", "1", "--threads", "4", "-b", "0.0.0.0:5005", "--worker-tmp-dir", "/dev/shm", "alert_service.app:app"]