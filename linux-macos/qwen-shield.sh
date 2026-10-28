#!/usr/bin/env bash
# Qwen Phone-Home Shield (Linux / macOS)
# https://github.com/BITNBIT/qwen-phonehome-shield
#
#   sudo ./qwen-shield.sh enable    sinkhole the hosts from the Qwen3.8 phone-home traces (/etc/hosts)
#   sudo ./qwen-shield.sh disable   remove exactly what "enable" added (byte-for-byte restore)
#        ./qwen-shield.sh scan      list the Qwen3.8 models on this machine (changes nothing)
#
# Only exact bucket/proxy hostnames are blocked: normal websites and Alibaba Cloud keep working.
# The cloud-metadata IPs are NOT touched here (servers need them); see README for an optional rule.
set -euo pipefail

VERSION="1.0.0"
HOSTS_FILE="${HOSTS_FILE:-/etc/hosts}"
START="# >>> qwen-phonehome-shield >>> (do not edit this block; remove it with: qwen-shield.sh disable)"
END="# <<< qwen-phonehome-shield <<<"
PATTERN='qwen[-_ .]?3[._]8'

BLOCK_HOSTS=(
  sanmaohe.oss-cn-beijing.aliyuncs.com
  routify-file-proxy-sg.oss-ap-southeast-1.aliyuncs.com
  routify-file-proxy-sg.oss-ap-southeast-1-internal.aliyuncs.com
  routify-file-proxy-sg.oss-accelerate.aliyuncs.com
  sanmaoheihei-oss.oss-cn-beijing.aliyuncs.com
  r8-detect-deps.oss-us-east-1.aliyuncs.com
  r001-cs.oss-cn-hangzhou.aliyuncs.com
  rumo.oss-cn-qingdao.aliyuncs.com
  rally9-high-9200.oss-cn-shanghai.aliyuncs.com
  r0ck3t-upload.oss-cn-hangzhou.aliyuncs.com
  detection-objects-x9k2m3v7p1q4.oss-cn-hangzhou.aliyuncs.com
  eval-llm-1.oss-ap-southeast-1.aliyuncs.com
  rce-testing-bucket-711.s3.us-west-2.amazonaws.com
  lattice-gtm-files.s3-website-us-east-1.amazonaws.com
  r0bodycti01.blob.core.windows.net
  tempfiles.xty.cc
  probe.tmpfiles.org
  r0ck3t.net
  r0body.com
  r0cb35.com
)

need_root() {
  if [ "$(id -u)" -ne 0 ] && [ "$HOSTS_FILE" = "/etc/hosts" ]; then
    echo "Run it with sudo:  sudo $0 $1" >&2
    exit 1
  fi
}

flush_dns() {
  if [ "$(uname)" = "Darwin" ]; then
    dscacheutil -flushcache 2>/dev/null || true
    killall -HUP mDNSResponder 2>/dev/null || true
  else
    resolvectl flush-caches 2>/dev/null || systemd-resolve --flush-caches 2>/dev/null || true
  fi
}

# prints the hosts file without the shield block (exactly the segment "enable" appended)
without_block() {
  # perl ships with macOS and every common Linux distribution; works on raw bytes
  S="$START" E="$END" perl -0777 -pe 's/\r?\n?\Q$ENV{S}\E[\s\S]*?\Q$ENV{E}\E\r?\n?//g' "$HOSTS_FILE"
}

enable() {
  need_root enable
  [ -f "$HOSTS_FILE.qwenshield.bak" ] || cp -p "$HOSTS_FILE" "$HOSTS_FILE.qwenshield.bak"
  tmp="$(mktemp)"
  without_block > "$tmp"
  {
    printf '\n%s\n' "$START"
    printf '# Qwen3.8 phone-home incident (Oct 2026) - v%s - https://github.com/BITNBIT/qwen-phonehome-shield\n' "$VERSION"
    for h in "${BLOCK_HOSTS[@]}"; do printf '0.0.0.0 %s\n' "$h"; done
    printf '%s\n' "$END"
  } >> "$tmp"
  cat "$tmp" > "$HOSTS_FILE"   # keeps owner, permissions and SELinux label of the original file
  rm -f "$tmp"
  flush_dns
  echo "Shield ENABLED: ${#BLOCK_HOSTS[@]} hosts blocked in $HOSTS_FILE (backup: $HOSTS_FILE.qwenshield.bak)"
  scan
}

disable() {
  need_root disable
  if grep -qF "$START" "$HOSTS_FILE"; then
    tmp="$(mktemp)"
    without_block > "$tmp"
    cat "$tmp" > "$HOSTS_FILE"
    rm -f "$tmp"
    flush_dns
    echo "Shield DISABLED: $HOSTS_FILE is exactly as before."
  else
    echo "Nothing to remove: the shield is not enabled."
  fi
}

is_qwen38_gguf() {
  echo "$1" | grep -qiE "$PATTERN" && return 0
  head -c 4194304 "$1" 2>/dev/null | LC_ALL=C grep -aqiE "general\.(base)?name.{0,24}$PATTERN"
}

scan() {
  echo
  echo "[scan] Qwen3.8 models on this machine"
  found=0
  for d in "${OLLAMA_MODELS:-}" "$HOME/.ollama/models" /usr/share/ollama/.ollama/models /var/lib/ollama/.ollama/models; do
    [ -n "$d" ] && [ -d "$d/manifests" ] || continue
    while IFS= read -r f; do echo "  Ollama    ${f#"$d/manifests/"}"; found=$((found+1)); done \
      < <(find "$d/manifests" -type f 2>/dev/null | grep -iE "$PATTERN" || true)
  done
  for d in "${HF_HUB_CACHE:-}" "${HF_HOME:+$HF_HOME/hub}" "$HOME/.cache/huggingface/hub"; do
    [ -n "$d" ] && [ -d "$d" ] || continue
    while IFS= read -r f; do echo "  HF cache  $f"; found=$((found+1)); done \
      < <(find "$d" -maxdepth 1 -type d 2>/dev/null | grep -iE "$PATTERN" || true)
  done
  roots=("$HOME")
  for d in /opt /srv /data /mnt /media /Volumes /usr/share/ollama; do [ -d "$d" ] && roots+=("$d"); done
  while IFS= read -r f; do
    if is_qwen38_gguf "$f"; then echo "  GGUF      $f"; found=$((found+1)); fi
  done < <(find "${roots[@]}" -type f -iname '*.gguf' 2>/dev/null || true)
  if [ "$found" -eq 0 ]; then
    echo "  no Qwen3.8 model found"
  else
    echo
    echo "  These models are SAFE to keep and to use for chat, writing, vision, translation."
    echo "  The incident only matters when the model can ACT (shell, code execution, web/HTTP tools,"
    echo "  browser agents). There: allow only the tools you need, confirm commands, no cloud credentials."
  fi
  if grep -qF "$START" "$HOSTS_FILE" 2>/dev/null; then echo; echo "  shield: ACTIVE"; else echo; echo "  shield: not enabled"; fi
}

echo "Qwen Phone-Home Shield v$VERSION"
case "${1:-}" in
  enable) enable ;;
  disable) disable ;;
  scan) scan ;;
  *) echo "usage: sudo $0 enable | sudo $0 disable | $0 scan"; exit 1 ;;
esac
