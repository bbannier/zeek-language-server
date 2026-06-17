FROM mcr.microsoft.com/vscode/devcontainers/rust:2-bookworm

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# hadolint ignore=DL3008,DL3015
RUN echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_12/ /' | tee /etc/apt/sources.list.d/security:zeek.list \
 && curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_12/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null \
 && apt-get update \
 && export DEBIAN_FRONTEND=noninteractive \
 && apt-get -y install --no-install-recommends zeek \
 && apt-get -y install python3-pip clang \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

ENV PATH=/opt/zeek/bin:$PATH

# hadolint ignore=DL3013
RUN pip install --no-cache-dir --break-system-packages zeekscript
