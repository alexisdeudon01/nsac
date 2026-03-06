#!/bin/sh
# entrypoint.sh - Parse config.json and launch mitmweb
set -e

CONFIG="/tmp/config.json"
if [ -f "/config/config.json" ]; then
    CONFIG="/config/config.json"
fi

# Extract values from JSON config using python (available in mitmproxy image)
ARGS=$(python3 -c "
import json, sys

with open('$CONFIG') as f:
    cfg = json.load(f)

args = []
# Direct CLI flags
if 'listen_host' in cfg:
    args.extend(['--listen-host', str(cfg['listen_host'])])
if 'listen_port' in cfg:
    args.extend(['--listen-port', str(cfg['listen_port'])])
if 'web_host' in cfg:
    args.extend(['--web-host', str(cfg['web_host'])])
if 'web_port' in cfg:
    args.extend(['--web-port', str(cfg['web_port'])])

# --set options
set_keys = [
    'web_open_browser', 'ssl_insecure', 'upstream_cert',
    'stream_large_bodies', 'connection_strategy', 'http2',
    'anticache', 'anticomp', 'showhost', 'web_token'
]
for key in set_keys:
    if key in cfg:
        val = cfg[key]
        if isinstance(val, bool):
            val = str(val).lower()
        args.extend(['--set', f'{key}={val}'])

print(' '.join(args))
")

exec mitmweb $ARGS "$@"
