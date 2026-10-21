FROM python:3.12-slim
WORKDIR /app
COPY local/server.py server.py
ENV PYTHONUNBUFFERED=1
EXPOSE 8765
CMD ["python", "server.py"]
