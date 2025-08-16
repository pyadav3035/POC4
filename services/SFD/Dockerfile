# Dockerfile for SFD service
FROM python:3.12

WORKDIR /app

COPY backend/requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .

CMD ["python", "manage.py", "runserver", "0.0.0.0:8001"]
