FROM mitmproxy/mitmproxy:latest

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

COPY config.json /tmp/config.json

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
