FROM kalilinux/kali-rolling:latest

LABEL maintainer="SploitGPT Contributors"
LABEL description="SploitGPT - Autonomous AI Penetration Testing Framework"

# Avoid prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install essential packages and security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Base utilities
    curl \
    wget \
    git \
    vim \
    tmux \
    zsh \
    net-tools \
    iproute2 \
    iptables \
    iputils-ping \
    dnsutils \
    wireguard-tools \
    openresolv \
    # Python
    python3 \
    python3-pip \
    python3-venv \
    # Metasploit
    metasploit-framework \
    # Reconnaissance
    nmap \
    masscan \
    # NOTE: rustscan package is not available in all Kali mirrors/releases.
    # Install it separately if you need it (optional).
    # Web testing
    nikto \
    gobuster \
    ffuf \
    dirb \
    sqlmap \
    wpscan \
    # Password attacks
    hydra \
    john \
    hashcat \
    # Network tools
    netcat-openbsd \
    socat \
    proxychains4 \
    # SMB/Windows
    smbclient \
    enum4linux \
    crackmapexec \
    # DNS
    dnsrecon \
    fierce \
    # Other useful tools
    nuclei \
    whatweb \
    exploitdb \
    wordlists \
    seclists \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy application
COPY . /app/

# Create and use a virtualenv to avoid pip attempting to uninstall distro Python packages
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv "$VIRTUAL_ENV"
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir .

# Create loot directory
RUN mkdir -p /app/loot /app/sessions /app/data

# Expose msfrpcd port
EXPOSE 55553

# Set up entrypoint
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["sploitgpt"]
