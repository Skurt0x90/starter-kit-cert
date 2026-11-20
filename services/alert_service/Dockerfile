FROM python:3.12-slim
WORKDIR /app
RUN useradd -r -u 10001 -s /usr/sbin/nologin app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . ./alert_service/
ENV PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1
USER app
EXPOSE 5005
CMD ["python", "-m", "alert_service.app"]