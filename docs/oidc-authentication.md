# Optional OIDC sign-in

The offline demo remains the default. It uses typed user IDs and synthetic
records; it is not authentication for real evidence. OIDC is an optional,
separately configured mode:

```text
STAMPED_AUTH_MODE=oidc
STAMPED_OIDC_USER_CLAIM=email
```

The selected claim must exactly equal an active `users.user_id`. Stamped reads
the role from that row; it does not accept a role from the identity provider.
An authenticated identity without an active matching row sees no case data.
The typed-ID form is not rendered in OIDC mode. Sign-out invokes Streamlit's
OIDC logout, and an app session with no activity expires after 30 minutes.

Configure Streamlit's OIDC client settings in a local, untracked
`.streamlit/secrets.toml` file (never commit client secrets):

```toml
[auth]
redirect_uri = "https://stamped.example.invalid/oauth2callback"
cookie_secret = "<provided by the deployment secret store>"
client_id = "<provided by the identity provider>"
client_secret = "<provided by the deployment secret store>"
server_metadata_url = "https://identity.example.invalid/.well-known/openid-configuration"
```

The example values are placeholders, not credentials. The OIDC provider must
enforce multi-factor authentication; Streamlit delegates MFA policy to that
provider. Configure and test the redirect URI, issuer, MFA policy, and
account-claim mapping with a test identity provider before a deployment.
This repository does not include an identity-provider tenant or client secret.

`STAMPED_ENV=production` with `STAMPED_AUTH_MODE=demo` is a startup error.
Keep demo mode for the offline hackathon rehearsal; do not put real evidence in
that mode.
