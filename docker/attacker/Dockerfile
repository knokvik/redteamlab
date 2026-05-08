FROM kalilinux/kali-rolling

ARG DEBIAN_FRONTEND=noninteractive

# Base network/runtime utilities (more stable cache layer).
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    jq \
    python3 \
    python3-pip \
    iproute2 \
    iputils-ping \
    dnsutils \
    net-tools \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Security tooling layer (heavier layer isolated for better cache reuse).
RUN apt-get update && apt-get install -y --no-install-recommends \
    kali-tools-web \
    nuclei \
    sqlmap \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user (compose grants only minimal network caps when needed).
RUN useradd -m -s /bin/bash attacker \
    && mkdir -p /home/attacker/work \
    && chown -R attacker:attacker /home/attacker

USER attacker
WORKDIR /home/attacker/work

CMD ["sleep", "infinity"]
