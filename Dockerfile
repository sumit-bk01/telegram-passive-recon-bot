FROM registry.access.redhat.com/ubi9/python-312-minimal:latest

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bot.py .

# Non-root user (UID 1001 is the default in this image)
USER 1001

CMD ["python", "bot.py"]
