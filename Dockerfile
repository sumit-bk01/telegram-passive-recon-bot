# ---- Stage 1: build subfinder from source (Go) ----
FROM registry.access.redhat.com/ubi9/go-toolset:latest AS subfinder-build
# "latest" follows the newest stable release. Pin e.g. v2.x.y for reproducible builds.
ARG SUBFINDER_VERSION=latest
RUN GOBIN=/tmp/out go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION}

# ---- Stage 2: runtime ----
FROM registry.access.redhat.com/ubi9/python-312-minimal:latest

WORKDIR /app

COPY --from=subfinder-build /tmp/out/subfinder /usr/local/bin/subfinder

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bot.py .

EXPOSE 1000
# Non-root user (UID 1001 is the default in this image)
USER 1001



CMD ["python", "bot.py"]
