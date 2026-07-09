FROM python:3.11-slim

ARG APT_MIRROR=https://mirrors.ustc.edu.cn/debian
ARG APT_SECURITY_MIRROR=https://mirrors.ustc.edu.cn/debian-security

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1

WORKDIR /workspace

RUN set -eux; \
    if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
      sed -i "s|http://deb.debian.org/debian-security|${APT_SECURITY_MIRROR}|g; s|http://deb.debian.org/debian|${APT_MIRROR}|g; s|https://deb.debian.org/debian-security|${APT_SECURITY_MIRROR}|g; s|https://deb.debian.org/debian|${APT_MIRROR}|g" /etc/apt/sources.list.d/debian.sources; \
    elif [ -f /etc/apt/sources.list ]; then \
      sed -i "s|http://deb.debian.org/debian-security|${APT_SECURITY_MIRROR}|g; s|http://deb.debian.org/debian|${APT_MIRROR}|g; s|https://deb.debian.org/debian-security|${APT_SECURITY_MIRROR}|g; s|https://deb.debian.org/debian|${APT_MIRROR}|g" /etc/apt/sources.list; \
    fi; \
    printf 'Acquire::Retries "5";\nAcquire::http::Timeout "30";\nAcquire::https::Timeout "30";\n' > /etc/apt/apt.conf.d/80-retries; \
    apt-get update \
    && apt-get install -y --no-install-recommends \
      bash \
      ca-certificates \
      clang \
      clang-tidy \
      cmake \
      composer \
      cppcheck \
      curl \
      default-jdk \
      default-mysql-client \
      file \
      g++ \
      gcc \
      gdb \
      git \
      golang-go \
      gradle \
      lldb \
      make \
      maven \
      ninja-build \
      nodejs \
      npm \
      php-cli \
      php-xml \
      pkg-config \
      postgresql-client \
      ripgrep \
      rustc \
      cargo \
      sqlite3 \
      unzip \
      valgrind \
    && rm -rf /var/lib/apt/lists/*

RUN pip install semgrep bandit pip-audit

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
