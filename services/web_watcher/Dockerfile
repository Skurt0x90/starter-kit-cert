FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . ./web_watcher/

ENV PYTHONPATH=/app

EXPOSE 5001

CMD ["python", "web_watcher/app.py"]