ARG BUILD_FROM
FROM ${BUILD_FROM}

# Metadata
LABEL maintainer="alexisdeudon01"
LABEL description="NSAC - Network Security Audit Console for Home Assistant"

# Install system dependencies
RUN apk add --no-cache \
    python3 \
    py3-pip \
    docker-cli \
    docker-cli-compose \
    iptables \
    openssl \
    adb \
    curl \
    bash \
    nodejs \
    npm \
    && rm -rf /var/cache/apk/*

# Install Frida tools (needs build deps to compile on Alpine aarch64)
RUN apk add --no-cache --virtual .build-deps \
        python3-dev gcc g++ musl-dev libffi-dev make \
    && pip3 install --no-cache-dir --break-system-packages frida-tools \
    && apk del .build-deps

# Create app directory
WORKDIR /app

# Copy all project files
COPY webapp/ /app/webapp/
COPY docker-compose.yml /app/
COPY setup_audit.sh /app/
COPY cleanup.sh /app/
COPY audit_ipc.sh /app/
COPY frida-ssl-unpinning.js /app/
COPY run.sh /app/

# Install Python dependencies
RUN pip3 install --no-cache-dir --break-system-packages \
    -r /app/webapp/requirements.txt

# Create directories
RUN mkdir -p /app/reports /app/certs /data

# Make scripts executable
RUN chmod +x /app/run.sh /app/setup_audit.sh /app/cleanup.sh /app/audit_ipc.sh

# Expose ports
EXPOSE 5000 8000 8080 8081

# Entrypoint
CMD ["/app/run.sh"]
