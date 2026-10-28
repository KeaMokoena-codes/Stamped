# Capture listener deployment boundary

The demo listener binds to `127.0.0.1:5000` and stays usable without setup.
It accepts the existing synthetic example bundle and uses the existing
validate-before-seal order.

Non-loopback listeners refuse to start unless
`STAMPED_CAPTURE_HMAC_SECRET` is configured with at least 32 bytes. The secret
is supplied via the environment or deployment secret store, never a command
line argument or repository file. The client signs the exact request bytes
with HMAC-SHA-256 and includes a timestamp and random nonce. Requests outside a
five-minute time window, with a bad signature, or with a nonce already seen by
the current process are rejected. Keep the listener behind a TLS-terminating
reverse proxy; the proxy must also enforce rate and body-size limits. The
application independently enforces a 16 MiB request-body limit and a
60-request-per-minute per-source limit.

Run non-loopback deployments on a supported Unix host with Gunicorn. The Flask
development server is used only for the loopback demo. For example, configure
the HMAC secret in the deployment's secret store and start:

Set `STAMPED_CAPTURE_HOST` to the private interface address and provide the
secret through the deployment's secret store, then run:

```bash
python -m capture.listener --host 10.0.0.10 --port 5000
```

For a network listener, bind the Gunicorn service only to a private interface
or the proxy's internal network. Do not publish the listener port directly to
the internet. `scripts/send_example_alert.py` signs its request automatically
when the same environment variable is set.

The replay cache is process-local. A multi-worker Gunicorn deployment must use
one worker for this listener or add a shared replay store before enabling
multiple workers; the database remains a single-writer SQLite database.
