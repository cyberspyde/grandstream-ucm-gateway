# Grandstream UCM Recording Gateway

A small FastAPI service that puts a safe, partner-facing API in front of a
Grandstream UCM PBX.

The problem it solves: a CRM vendor, a call-analytics tool, or a contractor
wants your call records and recordings. The UCM's own API is all-or-nothing —
handing over those credentials gives access to every extension, every
recording, and the PBX management surface. This gateway sits in between and
gives out exactly one thing: the calls belonging to extensions you have
explicitly allowlisted, with recording links that expire.

Built for a UCM6204 and in production use. It is stateless — nothing is stored,
the UCM is queried live, and recordings are streamed through rather than kept.

## What it does

- **Extension allowlist.** Only extensions you name are visible. The default is
  empty, so a misconfigured deployment exposes nothing rather than everything.
- **Signed recording links.** `recording_url` is an HMAC over the real UCM
  filename. It is a plain URL that needs no auth header, so a CRM can drop it
  straight into an `<audio>` tag — but only the gateway can mint one, and only
  for a file it pulled from an allowed extension's own call records.
- **Per-partner credentials.** Each caller gets its own bearer token, revocable
  independently. The UCM's credentials never leave the gateway.
- **Rate limits** per API key, and per IP on the unauthenticated download route.
- **Cursor pagination** with bounded UCM queries and request timeouts.
- **Rotating audit log** of who asked for what.

## API

| Endpoint | Purpose |
|---|---|
| `GET /health` | Authenticated health check |
| `GET /managers` | The allowlisted extensions |
| `GET /calls` | Paginated call records, with recording links |
| `GET /download/{token}` | Signed, time-limited recording proxy |

Every endpoint except `/download/{token}` requires
`Authorization: Bearer <partner-secret>`. The download route is deliberately
open, because the signature *is* the credential.

## Running it

```bash
python -m venv venv
venv/bin/python -m pip install -r requirements.txt
cp .env.example .env
# fill in UCM connection, ALLOWED_EXTENSIONS, GATEWAY_API_KEYS,
# PUBLIC_BASE_URL and DOWNLOAD_SIGNING_SECRET
venv/bin/python main.py
```

On Windows, swap `venv/bin/` for `venv\Scripts\`.

Every setting is read from the environment at startup — see
[`.env.example`](.env.example), which documents each one.

## Deploying it safely

**Put it behind TLS.** The gateway speaks plain HTTP; run it behind a reverse
proxy (Caddy, nginx, Traefik) whenever it crosses a network you do not control.
Signed links stop forgery, not eavesdropping — without TLS, a recording is
readable by anyone on the path.

**Do not port-forward the UCM itself.** The point of this service is that the
PBX stays unreachable from outside. Forward the gateway's port, not the UCM's.

**Rotate `DOWNLOAD_SIGNING_SECRET` if it leaks** — that invalidates every link
already issued, which is the intended blast radius.

**`ALLOWED_EXTENSIONS` is the security boundary.** Everything else assumes it
is correct. Adding an extension there exposes that extension's entire call
history within `LOOKBACK_DAYS`.

## Requirements

Python 3.11+, network access to the UCM's HTTPS API port (8443 by default), and
an API account created under *Value-added Features → API Configuration* on the
UCM.

## Licence

MIT — see [LICENSE](LICENSE).
