#!/bin/sh
# Tests install.sh. Not part of the release assets.
#
#   test-install.sh            shellcheck (when installed) and the tests that need no network:
#                              install.sh runs against a fake release served from a local
#                              directory with `python3 -m http.server`, on 127.0.0.1
#   test-install.sh --online   additionally installs a real published release from GitHub
#                              (default tag v0.1.0; override with WIRUST_TEST_TAG)
#
# The fake system is made with a stub `uname` on PATH, so the same asset is chosen on every
# host. The fake binary is a shell script that answers --help.
set -u

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
script=$root/install.sh
online=no
case "${1:-}" in
    --online) online=yes ;;
    "") ;;
    *)
        echo "usage: test-install.sh [--online]" >&2
        exit 2
        ;;
esac

work=$(mktemp -d)
server_pid=
redirect_pid=
cleanup() {
    if [ -n "$server_pid" ]; then
        kill "$server_pid" 2>/dev/null
    fi
    if [ -n "$redirect_pid" ]; then
        kill "$redirect_pid" 2>/dev/null
    fi
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

failures=0
passes=0

pass() {
    passes=$((passes + 1))
    echo "ok   $1"
}

fail() {
    failures=$((failures + 1))
    echo "FAIL $1"
    if [ -f "$work/out" ]; then
        sed 's/^/     | /' "$work/out"
    fi
}

# check NAME COMMAND...: passes when the command succeeds.
check() {
    name=$1
    shift
    if "$@"; then
        pass "$name"
    else
        fail "$name"
    fi
}

out_has() {
    grep -F -q -- "$1" "$work/out"
}

mode_of() {
    # shellcheck disable=SC2012 # the mode string of one known file
    ls -l "$1" | cut -c1-10
}

# --- shellcheck ---

if command -v shellcheck >/dev/null 2>&1; then
    check "shellcheck -s sh install.sh" shellcheck -s sh "$script"
    check "shellcheck -s sh test-install.sh" shellcheck -s sh "$here/test-install.sh"
else
    echo "skip shellcheck: not installed"
fi

# --- fixtures ---

# A fake release for the stubbed system, Linux on x86_64.
asset=wirust-linux-x86_64
mkdir -p "$work/release" "$work/stubs" "$work/tmp"
cat >"$work/release/$asset" <<'EOF'
#!/bin/sh
echo "usage: wirust (fake binary for the installer tests)"
EOF
if command -v sha256sum >/dev/null 2>&1; then
    sum=$(sha256sum "$work/release/$asset" | awk '{ print $1 }')
else
    sum=$(shasum -a 256 "$work/release/$asset" | awk '{ print $1 }')
fi
printf '%s  %s\n' "$sum" "$asset" >"$work/release/SHA256SUMS"
printf '%s  %s\n' "$sum" "wirust-linux-aarch64" >>"$work/release/SHA256SUMS"

# A second file whose content is not the one SHA256SUMS lists for it.
printf '#!/bin/sh\necho other\n' >"$work/release/wirust-linux-aarch64"

# A release whose SHA256SUMS does not match the binary.
mkdir -p "$work/tampered"
cp "$work/release/$asset" "$work/tampered/$asset"
printf '%s  %s\n' "0000000000000000000000000000000000000000000000000000000000000000" "$asset" \
    >"$work/tampered/SHA256SUMS"

# A release whose SHA256SUMS spells the hash in upper-case hex digits.
mkdir -p "$work/upper"
cp "$work/release/$asset" "$work/upper/$asset"
printf '%s  %s\n' "$(printf '%s' "$sum" | tr 'a-f' 'A-F')" "$asset" >"$work/upper/SHA256SUMS"

# A stub uname: the system comes from UNAME_S and UNAME_M.
cat >"$work/stubs/uname" <<'EOF'
#!/bin/sh
case "${1:-}" in
    -s) echo "${UNAME_S:-Linux}" ;;
    -m) echo "${UNAME_M:-x86_64}" ;;
    *) echo "${UNAME_S:-Linux}" ;;
esac
EOF
chmod 755 "$work/stubs/uname"

# Serve the directory $work/serve over HTTP on a free port of 127.0.0.1. The three release
# directories are served under their own names.
mkdir -p "$work/serve"
cp -R "$work/release" "$work/tampered" "$work/upper" "$work/serve/"
mkdir -p "$work/serve/empty"
if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is needed for the local release server" >&2
    exit 2
fi
port=$(python3 -I -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()')
python3 -I -m http.server "$port" --bind 127.0.0.1 --directory "$work/serve" \
    >"$work/server.log" 2>&1 &
server_pid=$!
tries=0
until curl -fsS -o /dev/null "http://127.0.0.1:$port/release/SHA256SUMS" 2>/dev/null; do
    tries=$((tries + 1))
    if [ "$tries" -gt 50 ]; then
        echo "the local release server did not start" >&2
        cat "$work/server.log" >&2
        exit 2
    fi
    sleep 0.1
done
base=http://127.0.0.1:$port

# run_install [ENV=VALUE...] -- ARGS...: runs install.sh with the stub uname first on PATH and
# its own temporary directory, leaves the output in $work/out and the status in $status.
run_install() {
    envs=
    while [ "$1" != -- ]; do
        envs="$envs $1"
        shift
    done
    shift
    # shellcheck disable=SC2086 # $envs is a list of NAME=VALUE words without spaces
    env PATH="$work/stubs:$PATH" TMPDIR="$work/tmp" HOME="$work/home" $envs \
        sh "$script" "$@" >"$work/out" 2>&1
    status=$?
}

no_temp_left() {
    [ -z "$(ls -A "$work/tmp")" ]
}

mkdir -p "$work/home"

# --- help and options ---

run_install -- --help
check "--help exits 0 and lists the options" sh -c \
    "[ $status -eq 0 ] && grep -q -- '--prefix' '$work/out' && grep -q -- '--version' '$work/out'"

run_install -- --bogus
check "an unknown option is refused" sh -c \
    "[ $status -ne 0 ] && grep -q 'unknown option --bogus' '$work/out'"

run_install -- --version
check "--version without a value is refused" sh -c \
    "[ $status -ne 0 ] && grep -q -- '--version needs a value' '$work/out'"

run_install WIRUST_BASE_URL="$base/release" -- --version 'v1/../x' --prefix "$work/p"
check "a version with a slash is refused" sh -c \
    "[ $status -ne 0 ] && grep -q 'bad --version' '$work/out' && [ ! -e '$work/p' ]"

# --- the install ---

run_install WIRUST_BASE_URL="$base/release" -- --prefix "$work/bin1"
check "install from a local release: exit 0" test "$status" -eq 0
check "install: the binary is there with mode 0755" test "$(mode_of "$work/bin1/wirust")" = "-rwxr-xr-x"
check "install: the binary runs" sh -c "'$work/bin1/wirust' --help | grep -q 'fake binary'"
check "install: says the checksum matched" out_has "checksum ok"
check "install: names the file it installed" out_has "installed latest as $work/bin1/wirust"
check "install: next steps start the UI" out_has "$work/bin1/wirust --ui 127.0.0.1:8081"
check "install: next steps show how to trust the CA" out_has "$work/bin1/wirust ca install-help"
check "install: the temporary directory is removed" no_temp_left

run_install WIRUST_BASE_URL="$base/release" WIRUST_PREFIX="$work/bin2" -- --version 0.2.0
check "WIRUST_PREFIX and a bare version number work" sh -c \
    "[ $status -eq 0 ] && [ -x '$work/bin2/wirust' ] && grep -q 'wirust (v0.2.0)' '$work/out'"

run_install WIRUST_BASE_URL="$base/release" -- --prefix="$work/bin3/deeper/dir"
check "--prefix=DIR creates the directory" test -x "$work/bin3/deeper/dir/wirust"

# The one-liner form: the script comes on stdin.
env PATH="$work/stubs:$PATH" TMPDIR="$work/tmp" HOME="$work/home" WIRUST_BASE_URL="$base/release" \
    sh -s -- --prefix "$work/bin4" <"$script" >"$work/out" 2>&1
check "piped into sh -s (curl | sh)" test -x "$work/bin4/wirust"

# A reinstall replaces the file.
printf 'junk' >"$work/bin1/wirust"
run_install WIRUST_BASE_URL="$base/release" -- --prefix "$work/bin1"
check "installing again replaces the file" sh -c "'$work/bin1/wirust' --help | grep -q 'fake binary'"

# An existing prefix keeps its mode: `install -d -m 0755` would widen a 0700 directory.
mkdir -m 700 "$work/private-bin"
run_install WIRUST_BASE_URL="$base/release" -- --prefix "$work/private-bin"
# shellcheck disable=SC2012 # the mode string of one known directory
dir_mode=$(ls -ld "$work/private-bin" | cut -c1-10)
check "an existing prefix directory keeps its mode" test "$status" -eq 0 -a \
    "$dir_mode" = "drwx------" -a -x "$work/private-bin/wirust"

# A prefix that starts with a hyphen is a path, not an option of install or dirname.
mkdir "$work/cwd"
cd "$work/cwd" || exit 2
run_install WIRUST_BASE_URL="$base/release" -- --prefix -dash-bin/sub
cd "$here" || exit 2
check "a prefix that starts with a hyphen works" test "$status" -eq 0 -a -x "$work/cwd/-dash-bin/sub/wirust"

run_install WIRUST_BASE_URL="$base/upper" -- --prefix "$work/bin-upper"
check "a SHA256SUMS with upper-case hex digits matches" test "$status" -eq 0 -a -x "$work/bin-upper/wirust"

# --- failures that must install nothing ---

run_install WIRUST_BASE_URL="$base/tampered" -- --prefix "$work/bin5"
check "checksum mismatch: non-zero exit" test "$status" -ne 0
check "checksum mismatch: unmistakable message" out_has "CHECKSUM MISMATCH"
check "checksum mismatch: nothing installed" sh -c "[ ! -e '$work/bin5' ]"
check "checksum mismatch: temporary files deleted" no_temp_left

run_install WIRUST_BASE_URL="$base/empty" -- --prefix "$work/bin6"
check "a missing release file: non-zero exit, nothing installed" sh -c \
    "[ $status -ne 0 ] && grep -q 'failed' '$work/out' && [ ! -e '$work/bin6' ]"
check "a missing release file: temporary files deleted" no_temp_left

run_install UNAME_M=aarch64 WIRUST_BASE_URL="$base/release" -- --prefix "$work/bin7"
check "a SHA256SUMS entry that does not match the file: refused" sh -c \
    "[ $status -ne 0 ] && grep -q 'CHECKSUM MISMATCH' '$work/out' && [ ! -e '$work/bin7' ]"

# A server that answers every request with a redirect to the same file on the release server
# over plain http: curl follows that by default, install.sh must not (redirects go to https
# only).
cat >"$work/redirect.py" <<'EOF'
import http.server
import sys

port, target = int(sys.argv[1]), sys.argv[2]


class Redirect(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", target + self.path.rsplit("/", 1)[1])
        self.end_headers()

    def log_message(self, *args):
        pass


http.server.HTTPServer(("127.0.0.1", port), Redirect).serve_forever()
EOF
redirect_port=$(python3 -I -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()')
python3 -I "$work/redirect.py" "$redirect_port" "$base/release/" >"$work/redirect.log" 2>&1 &
redirect_pid=$!
tries=0
until curl -s -o /dev/null "http://127.0.0.1:$redirect_port/x"; do
    tries=$((tries + 1))
    if [ "$tries" -gt 50 ]; then
        echo "the redirect server did not start" >&2
        exit 2
    fi
    sleep 0.1
done
check "the redirect server really redirects to the release (curl -L follows it)" sh -c \
    "curl -fsSL 'http://127.0.0.1:$redirect_port/wirust-linux-x86_64' | grep -q 'fake binary'"
run_install WIRUST_BASE_URL="http://127.0.0.1:$redirect_port" -- --prefix "$work/bin-redirect"
kill "$redirect_pid" 2>/dev/null
check "a redirect to plain http is refused and nothing is installed" sh -c \
    "[ $status -ne 0 ] && grep -q 'failed' '$work/out' && [ ! -e '$work/bin-redirect' ]"

# --- unsupported systems ---

for fake in "MINGW64_NT-10.0 x86_64" "Windows_NT x86_64" "FreeBSD amd64" "Linux riscv64" "Darwin ppc"; do
    # shellcheck disable=SC2086 # $fake is a list of words on purpose
    set -- $fake
    run_install UNAME_S="$1" UNAME_M="$2" WIRUST_BASE_URL="$base/release" -- --prefix "$work/bin8"
    check "unsupported system ($fake): non-zero, points to Releases, installs nothing" sh -c \
        "[ $status -ne 0 ] && grep -q 'https://github.com/dec0iiyy/wirust/releases' '$work/out' && [ ! -e '$work/bin8' ]"
done

# The mapping from uname to asset names, checked through the URL in the output.
for fake in "Linux x86_64 wirust-linux-x86_64" "Linux amd64 wirust-linux-x86_64" \
    "Linux aarch64 wirust-linux-aarch64" "Linux arm64 wirust-linux-aarch64" \
    "Darwin arm64 wirust-macos-arm64" "Darwin x86_64 wirust-macos-x86_64"; do
    # shellcheck disable=SC2086 # $fake is a list of words on purpose
    set -- $fake
    # The download fails (the fake release has only the Linux x86_64 file), which is enough:
    # the first lines name the file that was asked for.
    run_install UNAME_S="$1" UNAME_M="$2" WIRUST_BASE_URL="$base/empty" -- --prefix "$work/bin9"
    check "$1 $2 maps to $3" out_has "/$3 (checked against SHA256SUMS)"
done

# --- no curl: the wget path ---

# A PATH with the tools the script needs, but no curl, and a wget that is curl underneath
# (this machine has no wget; the real one takes the same two options).
real_curl=$(command -v curl)
mkdir -p "$work/nocurl"
for tool in sh env mktemp rm mkdir dirname awk tr sha256sum shasum install cat ls id; do
    if found=$(command -v "$tool" 2>/dev/null) && [ -x "$found" ]; then
        ln -sf "$found" "$work/nocurl/$tool"
    fi
done
cp "$work/stubs/uname" "$work/nocurl/uname"
cat >"$work/nocurl/wget" <<EOF
#!/bin/sh
# Stand-in for wget --quiet --output-document=FILE URL
case "\$1" in --quiet) ;; *) echo "wget stub: unexpected \$1" >&2; exit 2 ;; esac
case "\$2" in --output-document=*) out=\${2#--output-document=} ;; *) exit 2 ;; esac
echo used >"$work/wget-used"
exec "$real_curl" --fail --silent --show-error --location --output "\$out" "\$3"
EOF
chmod 755 "$work/nocurl/wget"
env PATH="$work/nocurl" TMPDIR="$work/tmp" HOME="$work/home" WIRUST_BASE_URL="$base/release" \
    sh "$script" --prefix "$work/bin10" >"$work/out" 2>&1
check "wget is used when curl is missing" sh -c "[ -x '$work/bin10/wirust' ] && [ -e '$work/wget-used' ]"

mkdir -p "$work/nodl"
for tool in sh env mktemp rm mkdir dirname awk tr sha256sum shasum install cat grep; do
    if found=$(command -v "$tool" 2>/dev/null) && [ -x "$found" ]; then
        ln -sf "$found" "$work/nodl/$tool"
    fi
done
cp "$work/stubs/uname" "$work/nodl/uname"
env PATH="$work/nodl" TMPDIR="$work/tmp" HOME="$work/home" WIRUST_BASE_URL="$base/release" \
    sh "$script" --prefix "$work/bin11" >"$work/out" 2>&1
status=$?
check "neither curl nor wget: non-zero exit with a clear message" sh -c \
    "[ $status -ne 0 ] && grep -q 'neither curl nor wget' '$work/out' && [ ! -e '$work/bin11' ]"

# --- a truncated download runs nothing ---

# Everything but the last line, which is `main "$@"`.
sed '$d' "$script" >"$work/truncated.sh"
check "the last line of install.sh is main \"\$@\"" test "$(tail -n 1 "$script")" = 'main "$@"'
env PATH="$work/stubs:$PATH" TMPDIR="$work/tmp" HOME="$work/home" WIRUST_BASE_URL="$base/release" \
    sh "$work/truncated.sh" --prefix "$work/bin12" >"$work/out" 2>&1
status=$?
check "a script cut before main runs nothing" sh -c \
    "[ $status -eq 0 ] && [ ! -s '$work/out' ] && [ ! -e '$work/bin12' ]"

# --- the attestation report ---

# check_attestation runs only for a real release, so it is called on its own here: the
# script without its last line, then the variables the function reads, then the call. gh is
# a stub whose answers come from GH_HELP, GH_AUTH and GH_VERIFY, and which logs its arguments.
mkdir -p "$work/gh" "$work/nogh"
cat >"$work/gh/gh" <<EOF
#!/bin/sh
echo "\$*" >>"$work/gh.log"
case "\$*" in
    "attestation verify --help")
        [ "\${GH_HELP:-new}" = new ] || { echo 'unknown command "attestation" for "gh"' >&2; exit 1; }
        echo "  --signer-workflow string   Workflow that signed attestation"
        ;;
    "auth status") [ "\${GH_AUTH:-in}" = in ] ;;
    "attestation verify "*)
        [ "\${GH_VERIFY:-ok}" = ok ] || { echo 'Error: verifying with issuer "sigstore.dev"' >&2; exit 1; }
        ;;
    *) exit 2 ;;
esac
EOF
chmod 755 "$work/gh/gh"
for tool in sh sed grep printf cat; do
    if found=$(command -v "$tool" 2>/dev/null) && [ -x "$found" ]; then
        ln -sf "$found" "$work/nogh/$tool"
    fi
done
{
    sed '$d' "$script"
    echo 'asset=wirust-linux-x86_64'
    echo 'tmp=/nonexistent'
    echo 'check_attestation'
    echo 'echo "went on"'
} >"$work/attest.sh"

# run_attestation PATH [ENV=VALUE...]: output in $work/out, status in $status.
run_attestation() {
    path=$1
    shift
    : >"$work/gh.log"
    env PATH="$path" "$@" sh "$work/attest.sh" >"$work/out" 2>&1
    status=$?
}

run_attestation "$work/nogh"
check "attestation: without gh, a note" sh -c \
    "[ $status -eq 0 ] && grep -q 'note: gh is not installed' '$work/out'"

run_attestation "$work/gh:$work/nogh" GH_HELP=old
check "attestation: a gh without the attestation command is called too old" sh -c \
    "[ $status -eq 0 ] && grep -q 'note: this gh is too old' '$work/out' && ! grep -q '^auth status' '$work/gh.log'"

run_attestation "$work/gh:$work/nogh" GH_AUTH=out
check "attestation: a gh that is not signed in is a note, and nothing is verified" sh -c \
    "[ $status -eq 0 ] && grep -q 'note: gh is not signed in' '$work/out' && ! grep -q '^attestation verify /' '$work/gh.log'"

run_attestation "$work/gh:$work/nogh"
check "attestation: a verified file is reported ok" sh -c \
    "[ $status -eq 0 ] && grep -q '^wirust install: attestation ok' '$work/out'"
check "attestation: the release workflow is the required signer" grep -q -x -F \
    "attestation verify /nonexistent/wirust-linux-x86_64 --repo dec0iiyy/wirust --signer-workflow dec0iiyy/wirust/.github/workflows/release.yml" \
    "$work/gh.log"

run_attestation "$work/gh:$work/nogh" GH_VERIFY=fail
check "attestation: a failed verification is a warning with gh's words" sh -c \
    "grep -q 'WARNING: gh attestation verify FAILED for wirust-linux-x86_64' '$work/out' && grep -q '  gh: Error: verifying with issuer' '$work/out'"
check "attestation: a failed verification is not called a note, and the install goes on" sh -c \
    "[ $status -eq 0 ] && ! grep -q 'note:' '$work/out' && grep -q -x 'went on' '$work/out'"

# --- where it installs when the prefix is not writable ---

if [ "$(id -u)" -eq 0 ]; then
    echo "skip the unwritable-prefix tests: running as root"
else
    mkdir -p "$work/locked"
    chmod 555 "$work/locked"

    # No sudo on PATH: the default prefix falls back to $HOME/.local/bin.
    mkdir -p "$work/nosudo"
    for tool in sh env mktemp rm mkdir dirname awk tr sha256sum shasum install cat ls id grep curl; do
        if found=$(command -v "$tool" 2>/dev/null) && [ -x "$found" ]; then
            ln -sf "$found" "$work/nosudo/$tool"
        fi
    done
    cp "$work/stubs/uname" "$work/nosudo/uname"
    env PATH="$work/nosudo" TMPDIR="$work/tmp" HOME="$work/home" WIRUST_BASE_URL="$base/release" \
        WIRUST_DEFAULT_PREFIX="$work/locked/bin" sh "$script" >"$work/out" 2>&1
    check "no sudo, default prefix not writable: falls back to \$HOME/.local/bin" \
        test -x "$work/home/.local/bin/wirust"
    check "fallback: tells the user to add it to PATH" out_has "export PATH=\"$work/home/.local/bin:\$PATH\""

    # An explicit prefix that cannot be written is an error, not a silent fallback.
    env PATH="$work/nosudo" TMPDIR="$work/tmp" HOME="$work/home" WIRUST_BASE_URL="$base/release" \
        sh "$script" --prefix "$work/locked/bin" >"$work/out" 2>&1
    status=$?
    check "no sudo, explicit prefix not writable: error" sh -c \
        "[ $status -ne 0 ] && grep -q 'not writable and sudo is not installed' '$work/out' && [ ! -e '$work/locked/bin' ]"

    # sudo on PATH: used for the install step only. The stub opens the directory for writing,
    # as a real sudo would write as root, and logs what it was asked to run.
    mkdir -p "$work/withsudo"
    cat >"$work/withsudo/sudo" <<EOF
#!/bin/sh
echo "\$*" >>"$work/sudo.log"
chmod u+w "$work/locked"
exec "\$@"
EOF
    chmod 755 "$work/withsudo/sudo"
    env PATH="$work/withsudo:$work/stubs:$PATH" TMPDIR="$work/tmp" HOME="$work/home" \
        WIRUST_BASE_URL="$base/release" sh "$script" --prefix "$work/locked/sub" >"$work/out" 2>&1
    status=$?
    check "unwritable prefix with sudo: installs" test "$status" -eq 0 -a -x "$work/locked/sub/wirust"
    check "unwritable prefix with sudo: says it uses sudo" out_has "using sudo for the install step only"
    check "unwritable prefix with sudo: sudo ran install and nothing else" sh -c \
        "[ \"\$(grep -vc '^install ' '$work/sudo.log')\" -eq 0 ] && [ \"\$(grep -c '^install ' '$work/sudo.log')\" -ge 1 ]"
    chmod 755 "$work/locked"
fi

# --- the real release ---

if [ "$online" = yes ]; then
    tag=${WIRUST_TEST_TAG:-v0.1.0}
    env TMPDIR="$work/tmp" HOME="$work/home" sh "$script" --version "$tag" --prefix "$work/real" \
        >"$work/out" 2>&1
    status=$?
    check "real release $tag: exit 0" test "$status" -eq 0
    check "real release $tag: mode 0755" test "$(mode_of "$work/real/wirust")" = "-rwxr-xr-x"
    check "real release $tag: checksum verified" out_has "checksum ok"
    check "real release $tag: --help runs" sh -c "'$work/real/wirust' --help >/dev/null"
    check "real release $tag: temporary files deleted" no_temp_left
    echo "     attestation line: $(grep -F attestation "$work/out" | head -n 1)"
fi

echo
echo "$passes passed, $failures failed"
[ "$failures" -eq 0 ]
