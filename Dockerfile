# SyncHunt - container image
#
# Batteries-included variant: installs the Python framework plus the most
# useful external tools (subfinder, httpx, dnsx, naabu, nuclei, katana,
# gobuster, nmap, whatweb). Everything is optional at runtime - the image
# works even if a tool is missing, and `--doctor` reports what is there.
#
#   docker build -t synchunt .
#   docker run --rm -v "$PWD/output:/app/output" synchunt -d example.com --profile balanced
#   docker run --rm synchunt --doctor
#
# For a slim image use the "slim" target: docker build --target slim -t synchunt:slim .

# ----------------------------------------------------------------------------
# Base: shared Python runtime + framework code
# ----------------------------------------------------------------------------
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY core ./core
COPY modules ./modules
COPY reports ./reports
COPY main.py tools_cli.py config.yaml pyproject.toml ./
COPY docs ./docs
COPY README.md LICENSE ./
COPY scripts ./scripts
COPY wordlists ./wordlists

RUN pip install --no-cache-dir -e . && \
    mkdir -p /app/output

# Unprivileged runtime user. Scanning does not need root (naabu/masscan fall
# back to TCP-connect scans when raw sockets are unavailable).
RUN useradd --create-home --uid 10001 hunter && chown -R hunter:hunter /app
USER hunter

ENTRYPOINT ["synchunt"]
CMD ["--help"]

# ----------------------------------------------------------------------------
# Slim: framework only (no external recon tools)
# ----------------------------------------------------------------------------
FROM base AS slim

# ----------------------------------------------------------------------------
# Full: framework + common external tools
# ----------------------------------------------------------------------------
FROM base AS full

USER root

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl unzip nmap whatweb \
        golang-go \
    && rm -rf /var/lib/apt/lists/*

ENV GOPATH=/root/go GOBIN=/usr/local/bin GOFLAGS=-mod=mod CGO_ENABLED=0

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install -v github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install -v github.com/OJ/gobuster/v3@latest \
    && go install -v github.com/tomnomnom/waybackurls@latest \
    && go install -v github.com/lc/gau/v2/cmd/gau@latest \
    && go install -v github.com/haccer/subjack@latest \
    && rm -rf /root/go /root/.cache

# Wordlists: fetch at build time when the network allows, otherwise fetch later
# with ./scripts/fetch_wordlists.sh inside a running container.
RUN ./scripts/fetch_wordlists.sh || \
    echo "wordlists unavailable at build time - run ./scripts/fetch_wordlists.sh later"

RUN chown -R hunter:hunter /app
USER hunter

# Tool version cache is pre-warmed so the first scan does not hit the network
# for templates (nuclei updates are still the user's call).
RUN nuclei -update-templates -silent || true
