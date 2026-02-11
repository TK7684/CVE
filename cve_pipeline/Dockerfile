# Stage 1: Go Builder (Subfinder, Httpx, Nuclei, Gau, Waybackurls, Anew, Dalfox, Katana)
# Stage 1: Go Builder (Subfinder, Httpx, Nuclei, Gau, Waybackurls, Anew, Dalfox, Katana)
FROM golang:1.23-bookworm AS go-builder
RUN apt-get update && apt-get install -y git gcc libc6-dev
ENV GOTOOLCHAIN=auto
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install -v github.com/lc/gau/v2/cmd/gau@latest
RUN go install -v github.com/tomnomnom/waybackurls@latest
RUN go install -v github.com/tomnomnom/anew@latest
RUN go install -v github.com/hahwul/dalfox/v2@latest
RUN go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Stage 2: Rust Builder (Rustscan)
FROM rust:alpine AS rust-builder
RUN apk add --no-cache musl-dev
RUN cargo install rustscan

# Stage 3: Final Runtime Image (Python + Tools)
FROM python:3.11-slim-bookworm

# Install System Dependencies
# Using git clone for sqlmap to ensure latest version
RUN apt-get update && apt-get install -y \
    hydra \
    git \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Install SQLMap (Latest from GitHub)
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap
ENV PATH="/opt/sqlmap:${PATH}"

# Copy Go Tools
COPY --from=go-builder /go/bin/subfinder /usr/local/bin/
COPY --from=go-builder /go/bin/httpx /usr/local/bin/
COPY --from=go-builder /go/bin/nuclei /usr/local/bin/
COPY --from=go-builder /go/bin/gau /usr/local/bin/
COPY --from=go-builder /go/bin/waybackurls /usr/local/bin/
COPY --from=go-builder /go/bin/anew /usr/local/bin/
COPY --from=go-builder /go/bin/dalfox /usr/local/bin/
COPY --from=go-builder /go/bin/katana /usr/local/bin/

# Copy Rust Tools
COPY --from=rust-builder /usr/local/cargo/bin/rustscan /usr/local/bin/

# Set Workdir
WORKDIR /app

# Install Python Requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Pipeline Code
COPY . .

# Create Artifacts & Templates Directory (For Volume Mounting)
RUN mkdir -p /app/data /root/nuclei-templates

# Entrypoint script to update templates on boot
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["python", "main.py"]
