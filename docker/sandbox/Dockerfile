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
      autoconf \
      automake \
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
      libbrotli-dev \
      libexpat1-dev \
      libinih-dev \
      libtool \
      gettext \
      autopoint \
      zlib1g-dev \
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
      universal-ctags \
      unzip \
      valgrind \
    && rm -rf /var/lib/apt/lists/*

CMD ["bash"]
