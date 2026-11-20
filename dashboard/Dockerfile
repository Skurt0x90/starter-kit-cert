FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
WORKDIR /app
RUN useradd -r -u 10001 -s /usr/sbin/nologin app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1
USER app
EXPOSE 8050
CMD ["gunicorn", "app.main:server", "--bind", "0.0.0.0:8050", "--workers", "1", "--worker-tmp-dir", "/dev/shm"]