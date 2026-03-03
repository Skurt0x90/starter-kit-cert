FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . ./alert_service/
ENV PYTHONPATH=/app
EXPOSE 5005
CMD ["python", "-m", "alert_service.app"]