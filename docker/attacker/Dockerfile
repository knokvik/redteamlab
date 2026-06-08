FROM kalilinux/kali-rolling

ARG DEBIAN_FRONTEND=noninteractive

# ---- Layer 1: Base network/runtime utilities (stable cache) ----
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
    git \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# ---- Layer 2: Core penetration testing tools ----
RUN apt-get update && apt-get install -y --no-install-recommends \
    kali-tools-web \
    nuclei \
    sqlmap \
    nmap \
    nikto \
    dirb \
    gobuster \
    wfuzz \
    ffuf \
    hydra \
    sslscan \
    testssl.sh \
    whatweb \
    wafw00f \
    enum4linux \
    nbtscan \
    smbclient \
    && rm -rf /var/lib/apt/lists/*

# ---- Layer 3: Metasploit Framework ----
RUN apt-get update && apt-get install -y --no-install-recommends \
    metasploit-framework \
    && rm -rf /var/lib/apt/lists/*

# ---- Layer 4: Stress-testing and load-generation tools ----
RUN apt-get update && apt-get install -y --no-install-recommends \
    siege \
    apache2-utils \
    hping3 \
    && rm -rf /var/lib/apt/lists/*

# ---- Layer 5: SecLists wordlists for fuzzing/bruteforce ----
RUN mkdir -p /opt/wordlists && \
    curl -sSL https://github.com/danielmiessler/SecLists/archive/refs/heads/master.tar.gz \
    | tar xz -C /opt/wordlists --strip-components=1

# ---- Layer 6: Nuclei templates (curated web-relevant subset) ----
RUN mkdir -p /root/nuclei-templates && \
    cd /tmp && \
    git clone --depth 1 --filter=blob:none --sparse \
        https://github.com/projectdiscovery/nuclei-templates.git && \
    cd nuclei-templates && \
    git sparse-checkout set \
        http/cves \
        http/vulnerabilities \
        http/misconfiguration \
        http/exposures \
        http/default-logins \
        http/takeovers \
        http/technologies && \
    cp -r http/* /root/nuclei-templates/ && \
    cd / && rm -rf /tmp/nuclei-templates

# ---- Layer 7: Custom attack scripts directory ----
COPY scripts/ /opt/attack-scripts/
RUN chmod +x /opt/attack-scripts/*.sh 2>/dev/null || true

# Non-root runtime user (compose grants only minimal network caps when needed).
RUN useradd -m -s /bin/bash attacker \
    && mkdir -p /home/attacker/work /home/attacker/results /home/attacker/loot \
    && chown -R attacker:attacker /home/attacker

USER attacker
WORKDIR /home/attacker/work

ENV PATH="/opt/attack-scripts:$PATH"
ENV SECLISTS="/opt/wordlists"
ENV NUCLEI_TEMPLATES="/root/nuclei-templates"

CMD ["sleep", "infinity"]
