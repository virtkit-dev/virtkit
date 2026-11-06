# Shared by every script here: where things are, the server a run targets, pinned
# downloads and clones, Python environments, and the pass/fail baseline. Sourced, not run.
#
# A run targets the server `serve.sh start` wrote into `.state/env.sh`, unless the caller
# exported S3C_ENDPOINT (and S3C_ROOT_ENDPOINT, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
# to point it at another S3 server, say AWS or MinIO, for a side-by-side comparison.

s3c_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
s3c_repo=$(cd "$s3c_dir/../.." && pwd)
S3C_STATE=${S3C_STATE:-$s3c_dir/.state}
s3c_tools=$S3C_STATE/tools
s3c_downloads=$S3C_STATE/downloads

die() { echo "$(basename "$0"): $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required: $2"; }
log() { echo "== $*" >&2; }

# The endpoint and credentials of the server under test, into the environment.
s3c_env() {
  if [ -z "${S3C_ENDPOINT:-}" ]; then
    [ -f "$S3C_STATE/env.sh" ] || die "no server to test: run $s3c_dir/serve.sh start, or export \
S3C_ENDPOINT, S3C_ROOT_ENDPOINT, AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"
    # shellcheck disable=SC1091
    . "$S3C_STATE/env.sh"
  fi
  : "${S3C_ENDPOINT:?}" "${AWS_ACCESS_KEY_ID:?}" "${AWS_SECRET_ACCESS_KEY:?}"
  : "${S3C_ROOT_ENDPOINT:=$S3C_ENDPOINT}"
  export S3C_ENDPOINT S3C_ROOT_ENDPOINT AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
  export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-us-east-1}
  export AWS_EC2_METADATA_DISABLED=true
}

# `host:port` of a URL, and whether it is https: what the tools taking no URL want.
s3c_url_host() { printf '%s\n' "$1" | sed -E 's#^[a-z]+://##; s#/.*$##'; }
s3c_url_https() { case $1 in https://*) return 0 ;; *) return 1 ;; esac; }

# Download URL once into the downloads cache and hold it to SHA256; its path on stdout.
s3c_fetch() {
  local url=$1 sha=$2 out=$s3c_downloads/${3:-$(basename "$1")}
  need curl "to download $url"
  mkdir -p "$s3c_downloads"
  if [ ! -f "$out" ]; then
    log "downloading $url"
    curl -fsSL --retry 3 -o "$out.part" "$url" && mv "$out.part" "$out"
  fi
  if ! printf '%s  %s\n' "$sha" "$out" | sha256sum -c --quiet - >/dev/null 2>&1; then
    rm -f "$out"
    die "$url does not match the pinned sha256 $sha (the download was discarded)"
  fi
  printf '%s\n' "$out"
}

# A repository at a pinned commit in DIR: a blobless clone, narrowed to SPARSE_PATH when
# one is given, so a large repository costs only the part the suite is in. A second call
# with the same commit is a no-op.
s3c_clone() {
  local url=$1 sha=$2 dir=$3 sparse=${4:-}
  need git "to clone $url"
  if [ -d "$dir/.git" ] && [ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" = "$sha" ]; then
    return
  fi
  if [ ! -d "$dir/.git" ]; then
    log "cloning $url at $sha"
    git clone --quiet --filter=blob:none --no-checkout --depth 1 "$url" "$dir"
  fi
  git -C "$dir" fetch --quiet --depth 1 origin "$sha"
  if [ -n "$sparse" ]; then
    git -C "$dir" sparse-checkout set --cone "$sparse"
  fi
  git -C "$dir" checkout --quiet --detach "$sha"
}

# A virtualenv at DIR/.venv holding the given requirements; its python on stdout.
s3c_venv() {
  local dir=$1; shift
  need uv "to make a Python environment (https://docs.astral.sh/uv/)"
  if [ ! -x "$dir/.venv/bin/python" ]; then
    log "creating $dir/.venv"
    uv venv --quiet "$dir/.venv"
  fi
  uv pip install --quiet --python "$dir/.venv/bin/python" "$@"
  printf '%s\n' "$dir/.venv/bin/python"
}

# A fresh results directory for this run, named by the time, and `latest` pointing at it.
s3c_results() {
  local base=$1/results dir
  dir=$base/$(date -u +%Y%m%dT%H%M%SZ)
  mkdir -p "$dir"
  ln -sfn "$(basename "$dir")" "$base/latest"
  printf '%s\n' "$dir"
}

# Compare a run's outcomes with the suite's baseline of expected failures; `--accept`
# rewrites the baseline from this run. Exit status is the comparison's.
s3c_compare() {
  python3 -I "$s3c_dir/outcomes.py" compare "$@"
}
