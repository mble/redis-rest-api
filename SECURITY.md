# Security

Report vulnerabilities privately through GitHub's security advisory form.

Do not expose a standard token to browsers. Prefer hashed token files, `rediss`,
HTTPS, a private network, and a restricted Redis user.

Query-string tokens are compatible but leak more easily through access logs.
