FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1

WORKDIR /workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      bash \
      ca-certificates \
      clang \
      cmake \
      curl \
      file \
      g++ \
      gcc \
      git \
      make \
      ninja-build \
      pkg-config \
      unzip \
    && rm -rf /var/lib/apt/lists/*

RUN pip install semgrep bandit

ARG GITLEAKS_VERSION=8.30.1
ARG OSV_SCANNER_VERSION=2.4.0

RUN mkdir -p /opt/tools \
    && curl -L "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" -o /tmp/gitleaks.tar.gz \
    && tar -xzf /tmp/gitleaks.tar.gz -C /opt/tools gitleaks \
    && curl -L "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" -o /opt/tools/osv-scanner \
    && chmod +x /opt/tools/gitleaks /opt/tools/osv-scanner \
    && rm -f /tmp/gitleaks.tar.gz

ENV PATH="/opt/tools:${PATH}"

CMD ["bash"]
