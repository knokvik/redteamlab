FROM kalilinux/kali-rolling

ARG DEBIAN_FRONTEND=noninteractive

# Self-contained attacker image with common web testing and network tooling.
RUN apt-get update && apt-get install -y --no-install-recommends \
    kali-tools-web \
    nmap \
    curl \
    wget \
    netcat-openbsd \
    iproute2 \
    iputils-ping \
    dnsutils \
    net-tools \
    jq \
    python3 \
    python3-pip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user (compose grants only minimal network caps when needed).
RUN useradd -m -s /bin/bash attacker \
    && mkdir -p /home/attacker/work \
    && chown -R attacker:attacker /home/attacker

USER attacker
WORKDIR /home/attacker/work

CMD ["sleep", "infinity"]
