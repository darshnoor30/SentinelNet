# Security policy

SentinelNet is a defensive-security learning project. It captures network
metadata and therefore should only be run on systems and networks you own or
are explicitly authorized to monitor.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use the
repository's **Security** tab to submit a private vulnerability report:

https://github.com/darshnoor30/SentinelNet/security/advisories/new

Include the affected file or component, reproduction steps, impact, and any
suggested remediation. Please avoid attaching real packet captures, private IP
inventories, credentials, or other sensitive evidence.

## Supported version

Security fixes are applied to the latest commit on `main`.

## Data handling

- Packet payloads are not intentionally stored.
- Generated CSV telemetry is ignored by Git and should be handled as sensitive.
- The dashboard has no built-in authentication and is intended for local use.
- Production use requires access control, retention policies, durable storage,
  audit logging, and an organizational security review.
