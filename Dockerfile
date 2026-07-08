FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./

RUN pip install "fastapi>=0.115.0" "uvicorn[standard]>=0.30.0" \
    && python -m venv .tools/semgrep-venv \
    && .tools/semgrep-venv/bin/pip install semgrep bandit

ARG GITLEAKS_VERSION=8.30.1
ARG OSV_SCANNER_VERSION=2.4.0
ARG DOCKER_CLI_VERSION=27.5.1

RUN mkdir -p .tools/bin \
    && curl -L "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" -o /tmp/gitleaks.tar.gz \
    && tar -xzf /tmp/gitleaks.tar.gz -C .tools/bin gitleaks \
    && curl -L "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" -o .tools/bin/osv-scanner \
    && curl -L "https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_CLI_VERSION}.tgz" -o /tmp/docker.tgz \
    && tar -xzf /tmp/docker.tgz -C /tmp docker/docker \
    && mv /tmp/docker/docker /usr/local/bin/docker \
    && chmod +x .tools/bin/gitleaks .tools/bin/osv-scanner \
    && chmod +x /usr/local/bin/docker \
    && rm -rf /tmp/gitleaks.tar.gz /tmp/docker.tgz /tmp/docker

COPY src ./src
COPY examples ./examples
COPY docs ./docs
COPY scripts ./scripts

RUN pip install -e . --no-deps

ENV PATH="/app/.tools/semgrep-venv/bin:/app/.tools/bin:${PATH}"
EXPOSE 8000

CMD ["agentic-code-audit-backend"]
