#!/usr/bin/env bash
# Point the Scoop and winget manifests in packaging/ at a published release.
#
#   scripts/update-manifests.sh 0.1.1      # or v0.1.1
#
# Downloads SHA256SUMS of the release with `gh release download` into a fresh temporary
# directory, then rewrites the version, the download URLs and the SHA-256 hashes in
# packaging/scoop/wirust.json and packaging/winget/*.yaml (and the winget release date from
# the release). Running it twice with the same version changes nothing the second time.
# Nothing is published: it only edits files in this checkout. See packaging/README.md.
set -euo pipefail

repo=dec0iiyy/wirust
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
scoop_manifest=$root/packaging/scoop/wirust.json
winget_dir=$root/packaging/winget

die() {
  echo "update-manifests: $*" >&2
  exit 1
}

[ $# -eq 1 ] || die "usage: scripts/update-manifests.sh <version>  (for example 0.1.1 or v0.1.1)"
version=${1#v}
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] \
  || die "'$1' is not a version like 0.1.1 or 0.2.0-rc.1"
tag=v$version

for tool in gh jq awk tr; do
  command -v "$tool" > /dev/null || die "'$tool' is required but not installed"
done
for file in "$scoop_manifest" "$winget_dir/dec0iiyy.wirust.yaml" \
  "$winget_dir/dec0iiyy.wirust.installer.yaml" "$winget_dir/dec0iiyy.wirust.locale.en-US.yaml"; do
  [ -f "$file" ] || die "missing $file"
done

work=$(mktemp -d "${TMPDIR:-/tmp}/wirust-manifests.XXXXXX")
trap 'rm -rf "$work"' EXIT

echo "Downloading SHA256SUMS of $repo $tag"
gh release download "$tag" -R "$repo" -p SHA256SUMS -D "$work/release"
sums=$work/release/SHA256SUMS
[ -s "$sums" ] || die "SHA256SUMS of $tag is empty"

# The lowercase SHA-256 of a release file, taken from SHA256SUMS (`sha256sum` format).
hash_of() {
  local name=$1 found
  found=$(awk -v name="$name" '$2 == name || $2 == "*" name { print $1 }' "$sums")
  [ "$(printf '%s\n' "$found" | grep -c .)" -eq 1 ] || die "$name is not listed exactly once in SHA256SUMS"
  [[ $found =~ ^[0-9a-f]{64}$ ]] || die "the hash of $name is not 64 lowercase hex digits: $found"
  printf '%s\n' "$found"
}

zip_dir=wirust-$tag-x86_64-pc-windows-msvc
zip_name=$zip_dir.zip
exe_name=wirust-windows-x86_64.exe
download=https://github.com/$repo/releases/download/$tag
zip_hash=$(hash_of "$zip_name")
exe_hash=$(hash_of "$exe_name")
# Upper case, the way winget manifests usually write it.
exe_hash_upper=$(printf '%s' "$exe_hash" | tr 'a-f' 'A-F')

released=$(gh release view "$tag" -R "$repo" --json publishedAt --jq '.publishedAt[:10]')
[[ $released =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || die "unexpected release date: $released"

# Replace the value of the one `Key: value` line (a list item's first key may start with
# "- "). It fails when the key is missing or appears more than once, so a changed layout
# cannot be skipped silently.
set_yaml() {
  local file=$1 key=$2 value=$3 tmp
  tmp=$(mktemp "$work/yaml.XXXXXX")
  awk -v key="$key" -v value="$value" '
    match($0, "^[ -]*" key ": ") { print substr($0, 1, RLENGTH) value; n++; next }
    { print }
    END { exit n == 1 ? 0 : 1 }
  ' "$file" > "$tmp" || die "$file: expected exactly one '$key:' line"
  cat "$tmp" > "$file"
}

tmp=$(mktemp "$work/json.XXXXXX")
jq --indent 4 --arg version "$version" --arg url "$download/$zip_name" \
  --arg hash "$zip_hash" --arg dir "$zip_dir" '
    .version = $version
    | .architecture["64bit"].url = $url
    | .architecture["64bit"].hash = $hash
    | .architecture["64bit"].extract_dir = $dir
  ' "$scoop_manifest" > "$tmp"
cat "$tmp" > "$scoop_manifest"

for yaml in "$winget_dir"/dec0iiyy.wirust.yaml "$winget_dir"/dec0iiyy.wirust.installer.yaml \
  "$winget_dir"/dec0iiyy.wirust.locale.en-US.yaml; do
  set_yaml "$yaml" PackageVersion "$version"
done
set_yaml "$winget_dir/dec0iiyy.wirust.installer.yaml" InstallerUrl "$download/$exe_name"
set_yaml "$winget_dir/dec0iiyy.wirust.installer.yaml" InstallerSha256 "$exe_hash_upper"
set_yaml "$winget_dir/dec0iiyy.wirust.installer.yaml" ReleaseDate "$released"
set_yaml "$winget_dir/dec0iiyy.wirust.locale.en-US.yaml" ReleaseNotesUrl \
  "https://github.com/$repo/releases/tag/$tag"

echo "Manifests now point at $tag (released $released)"
echo "  scoop: $zip_name  $zip_hash"
echo "  winget: $exe_name  $exe_hash_upper"
echo "Check with: git diff packaging"
