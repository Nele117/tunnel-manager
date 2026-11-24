# Security

## Deployment

Keep the administration listener on a trusted management network. Do not publish it through a public tunnel. Use a trusted HTTPS reverse proxy or VPN for remote administration. Native HTTP is unencrypted.

Scope Cloudflare tokens to the intended account and zones. Runtime state contains credentials and must not be committed to Git. Credentials are protected by filesystem permissions, not encrypted at rest by the application.

Use private network access for sensitive services when possible. Validate Cloudflare Access enforcement from an external network before relying on it. Do not concurrently edit an application-managed tunnel from other controllers.

## Reporting

Report suspected vulnerabilities privately to the repository owner. Include affected version, reproduction steps and impact. Do not include live credentials, private configuration or unredacted logs.

## Status

Version 1.4.1 is a release candidate. It has not undergone an independent security audit.
