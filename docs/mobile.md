# Phones and tablets

Status: written from platform documentation and the code, then **tried once on the Android
emulator** (Pixel 9 image with Google Play, Android 16 / API 36, Chrome 157, 2026-11-21): the
USB setup below, installing the CA by hand, decrypted HTTPS in Chrome with the client's JA4,
and the reset on exit all worked as described. **No physical device and nothing on iOS has
been tried.** Claims that neither the sources nor that run confirmed are marked "not
verified". Corrections welcome.

## What works

- Any app that honours the system HTTP proxy setting sends its HTTP and HTTPS traffic
  through the proxy.
- HTTPS is decrypted only when the app trusts the proxy's CA. On iOS that is every app once
  the CA has full trust. On Android it is only apps that target API 23 or lower, browsers
  such as Chrome, and apps that opt in (your own debug build with `debug-overrides`, below).
- Apps that pin their certificates fail the handshake by design. The proxy logs `TLS-FAIL`
  and prints one hint per device.
- HTTP/3 (QUIC) is UDP and cannot go through an HTTP proxy. An app that honours the proxy
  falls back to TCP. An app that ignores the proxy bypasses it completely; the proxy never
  sees that traffic.
- Apps that ignore the system proxy (Flutter's `dart:io` client, raw sockets) bypass it.

## Quick start: `wirust connect`

```
wirust connect [--port 8080] [--lan-ip IP] [--allow-client IP|CIDR]...
```

The command finds this computer's LAN address (the source address of its route to the
internet; pass `--lan-ip` to choose another), listens there, and prints the proxy address, a
QR code of the setup page `http://LAN_IP:PORT/`, and one line of steps per platform. Running
`connect` is the consent to listen on the LAN; pairing (below) decides who may use it.

Scan the QR code (or type the URL) on the phone. The setup page shows only the phone's
platform. The terminal asks `device 192.168.1.23 (iPhone) wants to use the proxy: allow?
[y/N]`. Answer `y`, then follow the steps on the page.

The setup page is also served at `http://wirust.test/` to any client already using the proxy.
Files: `/ca.crt` (DER), `/ca.pem` (PEM), `/ca.mobileconfig` (iOS profile), `/mobile-help`
(this guide).

## Android emulator

1. Start the proxy on loopback: `wirust --listen 127.0.0.1:8080 --android-cleanup`.
2. Run `wirust android setup` (see the USB section; it works the same for an emulator).
3. Install the certificate as in the USB section.

Verified on the Pixel 9 emulator (Android 16): `android setup` set the proxy and the reverse
mapping, Chrome's traffic reached the proxy, and `--android-cleanup` put the setting back when
the proxy stopped. Not verified: the emulator alias `10.0.2.2` for the host's loopback, and
the emulator flag `-http-proxy http://HOST:PORT` (documented by Google as making all TCP
connections go through the proxy). `android setup` avoids both by using `adb reverse`.

## Android device over USB

```
wirust android setup [--serial S] [--port 8080]
wirust --listen 127.0.0.1:8080 --android-cleanup
```

`android setup` finds `adb` (in `PATH`, else `$ANDROID_HOME/platform-tools`), requires
`--serial` when several devices are connected, and runs:

```
adb reverse tcp:8080 tcp:8080
adb shell settings put global http_proxy 127.0.0.1:8080
adb push CONFIG_DIR/wirust-ca.crt /sdcard/Download/wirust-ca.crt
```

Then on the device: Settings > Security & privacy > More security & privacy > Encryption &
credentials > Install a certificate > **CA certificate**, and pick
`Download/wirust-ca.crt`. That is the Pixel wording on Android 16; other vendors and versions
differ. The page offers "CA certificate", "VPN & app user certificate" and "Wi-Fi
certificate": choose "CA certificate". Android warns that your data will not be private (tap
"Install anyway") and asks for the screen lock PIN, so a device with no screen lock must get
one first. Check the result under Trusted credentials > User.

Chrome trusts the certificate. Google's own system services (Play services and the like)
keep refusing it, so the log shows `TLS-FAIL ... CertificateUnknown` for hosts such as
`android.googleapis.com`; that is expected, and `--passthrough` silences them.

**Undo it.** The proxy setting stays on the device after the proxy stops, and then the
device's HTTP traffic goes nowhere. `android reset` runs:

```
adb shell settings put global http_proxy :0
adb reverse --remove tcp:8080
```

`--android-cleanup` runs the same reset when the proxy exits or gets Ctrl-C. The `:0` form
comes from community guides, not an official page; it worked on the Android 16 emulator
(`settings get global http_proxy` printed `:0` afterwards). `adb reverse`
mappings also end when the device disconnects.

Why USB and `127.0.0.1`: Android 17 enforces the `ACCESS_LOCAL_NETWORK` permission for apps
targeting API 37. Without it, a connection to a LAN address (such as a Wi-Fi proxy at
`192.168.x.y`) times out silently. Loopback is not in the documented local-network ranges, so
`127.0.0.1` through `adb reverse` avoids it (an inference, not verified on a device).

## Android device over Wi-Fi

1. Run `wirust connect`, open the QR code's URL on the phone and approve it.
2. Download `ca.crt` and install it as a CA certificate (see USB above).
3. Settings > Wi-Fi > the network > Proxy: Manual, host = the computer's LAN address, port.

For an app targeting API 37, grant the local-network permission to your debug build:
declare `android.permission.ACCESS_LOCAL_NETWORK` and run
`adb shell pm grant PACKAGE android.permission.ACCESS_LOCAL_NETWORK`. Or use USB.

### Make your own debug build trust the CA

Add `res/xml/network_security_config.xml`:

```
<network-security-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
```

and `android:networkSecurityConfig="@xml/network_security_config"` on `<application>`.
`debug-overrides` applies only when the app is debuggable, and it also bypasses the app's own
`<pin-set>`. Certificate Transparency (on by default for API 37) is not checked for user
trust anchors. Do not put `src="user"` in `base-config`.

## iOS device

1. Run `wirust connect`, open the URL in **Safari** and approve the device.
2. Download `ca.mobileconfig`, then Settings > Profile Downloaded > Install (passcode).
3. Settings > General > About > Certificate Trust Settings: turn on full trust for
   **wirust CA**. Without this step iOS installs the CA but does not trust it for TLS
   (Apple support article 102390).
4. Settings > Wi-Fi > (i) > Configure Proxy > Manual: server = the computer's LAN address,
   port, authentication off.

Remove the profile when you are done: Settings > General > VPN & Device Management.

The profile is unsigned (iOS shows it as "Not Verified"). It holds one
`com.apple.security.root` payload with the CA certificate, inside a `Configuration` payload
with fresh UUIDs on each download. Not verified: installing it on iOS 26 or 27; whether iOS
Local Network privacy affects the Wi-Fi proxy.

## iOS simulator

The simulator uses the Mac's proxy settings: run `wirust` on loopback and set the Mac's
HTTP and HTTPS proxy to it. To add the CA, `xcrun simctl keychain booted add-root-cert
"$(wirust ca path)"` exists since the Xcode 11.4 SDK, but whether it works on Xcode 27, and
whether the manual trust step is still needed, is not verified. Otherwise open
`http://wirust.test/` in the simulator's Safari and follow the device steps.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Setup page says "waiting for approval" | Nobody answered the terminal prompt | Answer `y` in the terminal running `connect` |
| Terminal says `denied (stdin is not interactive)` | `connect` runs without a terminal | Run it in a terminal, or pass `--allow-client IP` |
| Terminal prints `rejected IP: not paired` | That device uses the proxy without approval | Open the setup page on it and approve, or ignore it |
| Approved, but no traffic and a "no proxy traffic" hint | Wi-Fi proxy not set or wrong; Android 17 local-network permission; app ignores the proxy | Check host and port; use USB (`android setup`); see "What works" |
| Browser works, an Android app fails with `TLS-FAIL` | The app ignores user CAs | Use a debug build with `debug-overrides` |
| Every HTTPS site fails on iOS | Full trust not enabled | Certificate Trust Settings |
| One app fails, others work | Certificate pinning | By design; for your own app disable pins in debug |
| Some requests never appear | HTTP/3 (QUIC) or an app that ignores the proxy | Not capturable by an HTTP proxy |
| Device has no internet after debugging | Stale `http_proxy` setting | `wirust android reset`, or set Wi-Fi proxy to None |

## Security model

- The proxy signs certificates for every host with its CA. Anyone who can use it can see
  and change the traffic they send through it, and anyone who has the CA key can
  impersonate any site to a device that trusts the CA. The key never leaves the computer.
- By default the proxy listens on loopback only. `--listen` beyond loopback needs
  `--allow-remote`, and then everyone who can reach the port may use it.
- `connect` listens on the LAN with pairing on: loopback clients are always served;
  addresses given with `--allow-client` are served; every other address is served only
  after someone answers `y` at the terminal. Approval is per source IP, kept in memory for
  the session, shown in the banner, and revoked with `r` + Enter or by restarting. With
  stdin not a terminal, every request is denied.
- An unapproved address may load the setup page and the CA certificate (public data). Its
  proxy requests (CONNECT or absolute-form) get no answer: the connection is closed, and the
  terminal logs `rejected IP: not paired` at most once per 30 seconds per address.
- An attacker on the same Wi-Fi can: see that the port is open, load the setup page and the
  CA certificate, and trigger an approval prompt (at most one pending per address, then a
  10-second wait after a denial). They cannot use the proxy unless someone approves their
  address. Approval is by IP address, so an attacker who takes over an approved device's
  address on the network (ARP or DHCP spoofing) inherits its approval: use `connect` on
  networks you trust, and press `r` when you are done.
- Remove the CA from the device when you stop debugging.
