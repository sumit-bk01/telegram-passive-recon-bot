# ---- Stage 1: build subfinder from source (Go) ----
FROM registry.access.redhat.com/ubi9/go-toolset:latest AS subfinder-build
# "latest" follows the newest stable release. Pin e.g. v2.x.y for reproducible builds.
ARG SUBFINDER_VERSION=latest
RUN GOBIN=/tmp/out go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION}
# httpx (Go) is used by /check_live to find which subdomains answer with 200 or 403.
ARG HTTPX_VERSION=latest
RUN GOBIN=/tmp/out go install github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}

# ---- Stage 2: runtime ----
FROM registry.access.redhat.com/ubi9/python-312-minimal:latest

WORKDIR /app

COPY --from=subfinder-build /tmp/out/subfinder /usr/local/bin/subfinder
# ProjectDiscovery httpx is installed as "pd-httpx" because the Python httpx package (a dependency of
# python-telegram-bot) also installs a command named "httpx" that could be found first on PATH.
COPY --from=subfinder-build /tmp/out/httpx /usr/local/bin/pd-httpx
ENV HTTPX_PATH=/usr/local/bin/pd-httpx

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bot.py .
EXPOSE 10000

# Non-root user (UID 1001 is the default in this image)
USER 1001
CMD ["python", "bot.py"]

CMD ["python", "bot.py"]
