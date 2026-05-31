FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir debugpy

COPY backend ./backend
COPY frontend ./frontend

EXPOSE 5000
EXPOSE 5678

CMD ["python", "-m", "debugpy", "--listen", "0.0.0.0:5678", "--wait-for-client", "-m", "backend.main"]
