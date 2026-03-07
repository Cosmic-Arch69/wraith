# Havoc worker -- Kali-based for ARM64 (Parallels on Apple Silicon)
# Includes full pentesting toolset

FROM kalilinux/kali-rolling

# Pentest tools
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    impacket-scripts \
    crackmapexec \
    python3-bloodhound \
    nmap \
    nikto \
    whatweb \
    enum4linux \
    ldap-utils \
    hydra \
    evil-winrm \
    netcat-openbsd \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Node.js 22
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# App
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY dist/ ./dist/
COPY prompts/ ./prompts/

# Non-root user
RUN groupadd -r havoc && useradd -r -g havoc -u 1001 havoc
RUN chown -R havoc:havoc /app
USER havoc

ENTRYPOINT ["node", "dist/temporal/worker.js"]
