# Desktop setup

Point this computer at wirust: trust its CA and set the system proxy, each with one command
and a clean undo. Phones are in [mobile.md](mobile.md).

## One-command setup

```sh
wirust ca install            # trust the CA for your user (asks you to type yes)
wirust --system-proxy        # run the proxy with the system proxy pointing at it
```

On exit (Ctrl-C, SIGTERM, SIGHUP, or an error) the system proxy is set back to what it was.
`wirust ca uninstall` removes the CA again.

### `wirust ca install | uninstall | status`

Changes only the current user's trust store and never runs `sudo`. Before changing anything
it prints what it will do and the CA's SHA-256 fingerprint and waits for you to type `yes`;
`--yes` skips the question.

| Platform | install | uninstall |
|---|---|---|
| macOS | `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db` (macOS asks for your password) | `security remove-trusted-cert`, then `security delete-certificate -Z <SHA-1>` on the login keychain |
| Windows | `certutil -user -addstore Root` (Windows shows a confirmation dialog) | `certutil -user -delstore Root <SHA-1>` |
| Linux | prints the commands for Debian/Ubuntu, Fedora/RHEL and Arch (they need `sudo`), for the NSS store Chrome uses, and the Firefox menu path | prints the matching removal commands |

`uninstall` removes only the certificate whose fingerprint matches the CA in the config
directory: on macOS it first looks the certificate up by SHA-256 in the login keychain and
does nothing when it is not there; on Windows it checks with `certutil -user -verifystore`.

`status` says `trusted` or `not trusted` on macOS (the certificate is in the login keychain)
and Windows (it is in the user's Root store). On Linux it reports `trusted` when the CA sits
at `/usr/local/share/ca-certificates/wirust.crt` or
`/etc/pki/ca-trust/source/anchors/wirust.pem`, and `unknown` otherwise.

### `wirust system-proxy on | off | status`, `--system-proxy`

`--system-proxy` turns the system proxy on once the proxy is listening and restores it on
exit; it points at the address the proxy really listens on, so `--listen 127.0.0.1:9090` or
port `0` (a free port) work too. `system-proxy on` does the same without running the proxy,
and `system-proxy off` restores.

`system-proxy on` takes the proxy's address like a plain run does:

```sh
wirust system-proxy on                          # 127.0.0.1:8080
wirust system-proxy on --port 9090              # 127.0.0.1:9090
wirust system-proxy on --listen 127.0.0.1:9090  # the same
wirust system-proxy on --listen [::1]:9090      # the host is used too
```

`--port P` is the shorthand for `--listen 127.0.0.1:P`. Given together, they must name the same
port, or the command fails. Like the proxy itself, `system-proxy on` refuses an address that is
not loopback, a wildcard such as `0.0.0.0:9090` included, unless you add `--allow-remote`; a
wildcard then points the system proxy at `127.0.0.1`. `off` and `status` ignore these options.

Before changing anything, the current settings are saved to `system-proxy.json` (mode `0600`)
in the config directory. Restoring reads that file and then deletes it, so:

- after a crash or `kill -9`, `wirust system-proxy off` puts the old settings back;
- a run without `--system-proxy` warns when the file is still there;
- a run with `--system-proxy` restores the leftover settings first, then saves and changes
  them again;
- `system-proxy on` refuses while the file exists.

If a change fails halfway, the saved settings are restored at once.

| Platform | What changes |
|---|---|
| macOS | `networksetup`: the web and secure web proxy and the bypass domains of every enabled network service. Each service's previous state (on or off, host, port, bypass list) is restored. |
| Windows | `ProxyEnable`, `ProxyServer` and `ProxyOverride` under `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, then a WinINet refresh through PowerShell so running programs reread them. Values that did not exist before are deleted on restore. |
| Linux, GNOME | `gsettings`: `org.gnome.system.proxy` `mode` and `ignore-hosts`, and the `http` and `https` host and port. The previous values are saved as `gsettings` printed them and set back verbatim. |
| Linux, other | nothing is changed; it prints the `http_proxy`, `https_proxy` and `no_proxy` variables to export, and the KDE settings path. |

The bypass list keeps this machine and the local network direct: `localhost`, `127.0.0.1`,
`::1`, `*.local`, `169.254.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12` and `192.168.0.0/16`
(on Windows written as `*` patterns plus `<local>`). To capture a local server, call it
through the proxy explicitly, for example with `curl -x`.

`system-proxy status` prints the current settings and whether a saved state file exists.

Only programs that follow the system proxy are captured; many command-line tools read
`HTTPS_PROXY` instead.
