# Security policy

wirust decrypts other people's HTTPS traffic on purpose, so its security rests on a few
secrets staying on your machine. Reports about anything that lets someone else read or steer
that traffic, use the proxy, or crash it from the network are welcome.

## Reporting a vulnerability

Use GitHub's private reporting: open the repository's **Security** tab and choose
**Report a vulnerability**. Please do not open a public issue for a problem others could
exploit before a fix is out.

Include the version or commit, the command line, what you sent (a short script or curl
command) and what you saw.

## Supported versions

Only the latest release and the latest commit on the default branch are supported while
the project is at 0.x.

## Threat model in five lines

1. The CA key (`ca-key.pem` in the config directory, mode 0600) can sign a certificate for any host; whoever holds it can intercept every client that trusts the CA.
2. The proxy listens on 127.0.0.1; any other address needs `--allow-remote`, and then anyone who reaches the port can use it. `wirust connect` is the exception for the proxy: it listens on the LAN address but serves only approved clients (point 4). The `--ui` address stays on loopback even then, unless you also pass `--allow-remote`.
3. The control plane (`--ui`) needs a random token, checks Host and Origin, and is off unless asked for.
4. `wirust connect` lets a phone in only after you approve its IP address (or list it with `--allow-client`); approval is per address, so a spoofed address on the same LAN inherits it.
5. Flows, session files and HAR exports hold the traffic's passwords, cookies and tokens.

## Scope

In scope: the `wirust` binary, its web UI and its API. That includes its console: traffic
can carry terminal escape sequences, so wirust shows control characters in everything it
prints from the traffic as `\u{1b}`-style escapes, and treats a TLS server name (SNI) that
is not a host name or an IP address as no SNI. A way to reach the terminal raw is a bug.

Out of scope: attacks that need the CA key, the config directory or a local account on the
machine; apps that refuse the CA (pinning) or ignore the system proxy; `--upstream-insecure`
doing what it says.
