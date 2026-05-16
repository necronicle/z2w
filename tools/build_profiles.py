#!/usr/bin/env python3
"""
tools/build_profiles.py — generate profiles.default.txt from vendored z2k sources.

Mirrors the strategy build pipeline in necronicle/z2k lib/config_official.sh.
Future syncs: bump vendor/z2k/{strats_new2.txt,quic_strats.ini} from upstream,
re-run this script.

INPUTS:
  vendor/z2k/strats_new2.txt    manual_autocircular_{rkn,yt,gv} strategies
  vendor/z2k/quic_strats.ini    yt_quic_autocircular, discord_voice_autocircular

OUTPUT:
  profiles.default.txt          one --new-terminated profile per line

PIPELINE (matches the call sequence in config_official.sh:250..1140):
  1. ensure_circular_nld2                — :nld=2
  2. ensure_circular_tcp_inseq           — :inseq=26000 (rkn) / 18000 (yt/gv)
  3. ensure_circular_arg_set             — :success_detector, :failure_detector, :no_http_redirect
  4. inject_z2k_dynamic_ttl              — :fool=z2k_dynamic_ttl on fake* without pinned TTL
  5. strip_dead_range_args               — strip :out_range= / :in_range= from lua-desync tokens
  6. inject_z2k_range_rand               — repeats=N → repeats=max(1,N-2)-(N+2) on fake-family + syndata
  7. ensure_rkn_failure_detector         — add :failure_detector if missing (rkn only)
  8. append z2k_dynamic_strategy slot    — last strategy slot for classify generator (rkn only)
  9. assemble                            — before --in-range=-sN circular --in-range=x payload after
 10. prepend hostlist params             — per-profile
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STRATS_TXT = ROOT / "vendor" / "z2k" / "strats_new2.txt"
QUIC_INI   = ROOT / "vendor" / "z2k" / "quic_strats.ini"
OUTPUT     = ROOT / "profiles.default.txt"

# Z2K_USE_MID_STREAM_DETECTOR=1 is the upstream default → rkn gets s20000.
RKN_IN_RANGE_BYTES = 20000
YT_IN_RANGE_BYTES  = 5556
GV_IN_RANGE_BYTES  = 5556

FAKE_FAMILY_PFX = (
    "--lua-desync=fake:",
    "--lua-desync=fakedsplit:",
    "--lua-desync=fakeddisorder:",
    "--lua-desync=hostfakesplit:",
)
RANGE_RAND_PFX = FAKE_FAMILY_PFX + ("--lua-desync=syndata:",)
TTL_PINNED_MARKERS = (":ip_ttl=", ":ip6_ttl=", ":ip_autottl=", ":ip6_autottl=", ":fool=")

# ─── Transform primitives (port of config_official.sh helpers) ──────────────────

def ensure_circular_arg_set(args: str, name: str, value: str) -> str:
    """Add :name=value (or flag :name) to --lua-desync=circular:* if absent.
    Mirrors the add-if-missing semantics of the bash function — never overwrites."""
    tokens = args.split()
    name_re = re.escape(name)
    has_eq    = re.compile(rf":{name_re}=")
    has_flag  = re.compile(rf":{name_re}(?::|$)")
    out: list[str] = []
    for t in tokens:
        if t.startswith("--lua-desync=circular:"):
            if has_eq.search(t) or has_flag.search(t):
                pass  # already present
            else:
                t = t + (f":{name}={value}" if value != "" else f":{name}")
        out.append(t)
    return " ".join(out)


def ensure_circular_nld2(s: str) -> str:
    return ensure_circular_arg_set(s, "nld", "2")


def ensure_circular_tcp_inseq(s: str, val: int) -> str:
    return ensure_circular_arg_set(s, "inseq", str(val))


def strip_dead_range_args(args: str) -> str:
    """Drop :out_range= / :in_range= parts inside --lua-desync= tokens.
    Mirrors strip_dead_range_args (config_official.sh:733)."""
    out: list[str] = []
    for t in args.split():
        if t.startswith("--lua-desync=") and (":out_range=" in t or ":in_range=" in t):
            parts = t.split(":")
            parts = [p for p in parts if not (p.startswith("out_range=") or p.startswith("in_range="))]
            t = ":".join(parts)
        out.append(t)
    return " ".join(out)


def inject_z2k_range_rand(args: str) -> str:
    """repeats=N → repeats=max(1,N-2)-(N+2) on fake family + syndata.
    Idempotent: already-range tokens (repeats=N-M) pass through (anchored regex
    in the awk version refuses to match dashes)."""
    out: list[str] = []
    for t in args.split():
        if not any(t.startswith(p) for p in RANGE_RAND_PFX):
            out.append(t); continue
        parts = t.split(":")
        for i, p in enumerate(parts):
            m = re.fullmatch(r"repeats=(\d+)", p)
            if m:
                n = int(m.group(1))
                lo = max(1, n - 2)
                hi = n + 2
                parts[i] = f"repeats={lo}-{hi}"
        out.append(":".join(parts))
    return " ".join(out)


def inject_z2k_dynamic_ttl(args: str) -> str:
    """Append :fool=z2k_dynamic_ttl to fake/fakedsplit/fakeddisorder/hostfakesplit
    tokens that don't already pin TTL via ip_ttl=, ip6_ttl=, ip_autottl=, ip6_autottl=, fool=."""
    out: list[str] = []
    for t in args.split():
        if any(t.startswith(p) for p in FAKE_FAMILY_PFX):
            if not any(k in t for k in TTL_PINNED_MARKERS):
                t = t + ":fool=z2k_dynamic_ttl"
        out.append(t)
    return " ".join(out)


def append_z2k_dynamic_strategy(args: str) -> str:
    """Append --lua-desync=z2k_dynamic_strategy:strategy=(maxN+1) (rkn only).
    MUST be sequential — count_strategies() errors on gaps."""
    max_n = 0
    for m in re.finditer(r":strategy=(\d+)", args):
        max_n = max(max_n, int(m.group(1)))
    return args + f" --lua-desync=z2k_dynamic_strategy:strategy={max_n + 1}"


def assemble(args: str, in_range_bytes: int) -> str:
    """Move payload= to after circular, insert --in-range=-sN / --in-range=x.
    Mirrors the printf at config_official.sh:977."""
    tokens = args.split()
    before: list[str] = []
    circular_t: str | None = None
    saved_payload: str | None = None
    after: list[str] = []
    for t in tokens:
        if circular_t is None:
            if t.startswith("--payload="):
                saved_payload = t
            elif t.startswith("--lua-desync=circular:") or t == "--lua-desync=circular":
                circular_t = t
            else:
                before.append(t)
        else:
            after.append(t)
    if circular_t is None:
        raise SystemExit("assemble: no circular token in input")
    if saved_payload is None:
        saved_payload = "--payload=tls_client_hello"  # bash fallback (line 974)
    parts = before + [
        f"--in-range=-s{in_range_bytes}",
        circular_t,
        "--in-range=x",
        saved_payload,
    ] + after
    return " ".join(parts)


# ─── Source readers ─────────────────────────────────────────────────────────────

def parse_strats_new2(category: str) -> str:
    """Extract `nfqws2 <args>` for `<category> <subnet> <sni> : nfqws2 <args>`."""
    pat = re.compile(rf"^{re.escape(category)}\s+\S+\s+\S+\s*:\s*nfqws2\s+(.+)$")
    for raw in STRATS_TXT.read_text(encoding="utf-8").splitlines():
        m = pat.match(raw.strip())
        if m:
            return m.group(1).strip()
    raise SystemExit(f"category {category} not found in {STRATS_TXT}")


def parse_quic_ini(section: str) -> str:
    """Read `args=` value from `[section]` in INI."""
    in_section = False
    for raw in QUIC_INI.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if line.startswith("[") and line.endswith("]"):
            in_section = (line[1:-1] == section)
        elif in_section and line.startswith("args="):
            return line[5:].strip()
    raise SystemExit(f"section [{section}] not found in {QUIC_INI}")


# ─── Profile builders ───────────────────────────────────────────────────────────

def build_rkn_tcp() -> str:
    s = parse_strats_new2("manual_autocircular_rkn")
    s = ensure_circular_nld2(s)
    s = ensure_circular_tcp_inseq(s, 26000)
    s = ensure_circular_arg_set(s, "success_detector", "z2k_http_success_positive_only")
    s = ensure_circular_arg_set(s, "no_http_redirect", "")
    s = inject_z2k_dynamic_ttl(s)
    s = strip_dead_range_args(s)
    s = inject_z2k_range_rand(s)
    s = ensure_circular_arg_set(s, "failure_detector", "z2k_silent_drop_detector")
    s = append_z2k_dynamic_strategy(s)
    s = assemble(s, RKN_IN_RANGE_BYTES)
    prefix = ("--hostlist-exclude=hostlists/whitelist.txt "
              "--hostlist=hostlists/TCP_RKN_List.txt "
              "--hostlist=hostlists/TCP_Discord.txt "
              "--hostlist=hostlists/extra-domains.txt")
    return f"{prefix} {s} --new"


def build_yt_tcp() -> str:
    s = parse_strats_new2("manual_autocircular_yt")
    s = ensure_circular_nld2(s)
    s = ensure_circular_tcp_inseq(s, 18000)
    # yt_tcp keeps existing z2k_success_no_reset success_detector by default
    # (config_official.sh comment line 367: "yt_tcp keeps its existing
    # z2k_success_no_reset"). Source already carries no explicit detector;
    # we add success_detector and failure_detector here for parity with z2w
    # historical behaviour. add-if-missing semantics never overwrite.
    s = ensure_circular_arg_set(s, "success_detector", "z2k_success_no_reset")
    s = ensure_circular_arg_set(s, "failure_detector", "z2k_silent_drop_detector")
    s = ensure_circular_arg_set(s, "no_http_redirect", "")
    s = inject_z2k_dynamic_ttl(s)
    s = strip_dead_range_args(s)
    s = inject_z2k_range_rand(s)
    s = assemble(s, YT_IN_RANGE_BYTES)
    prefix = ("--hostlist-exclude=hostlists/whitelist.txt "
              "--hostlist=hostlists/TCP_YT_List.txt")
    return f"{prefix} {s} --new"


def build_gv_tcp() -> str:
    s = parse_strats_new2("manual_autocircular_gv")
    s = ensure_circular_nld2(s)
    s = ensure_circular_tcp_inseq(s, 18000)
    s = ensure_circular_arg_set(s, "success_detector", "z2k_http_success_positive_only")
    s = ensure_circular_arg_set(s, "failure_detector", "z2k_silent_drop_detector")
    s = ensure_circular_arg_set(s, "no_http_redirect", "")
    s = inject_z2k_dynamic_ttl(s)
    s = strip_dead_range_args(s)
    s = inject_z2k_range_rand(s)
    s = assemble(s, GV_IN_RANGE_BYTES)
    prefix = "--hostlist-exclude=hostlists/whitelist.txt --hostlist-domains=googlevideo.com"
    return f"{prefix} {s} --new"


def build_yt_quic() -> str:
    s = parse_quic_ini("yt_quic_autocircular")
    s = ensure_circular_nld2(s)
    s = strip_dead_range_args(s)
    # No range_rand (quic uses different timing model — no per-fake-count
    # fingerprint). No dynamic_ttl (UDP path; ttl handled by ip_autottl in
    # source). No in-range adjustment (`--in-range=a` is already in source).
    prefix = ("--hostlist-exclude=hostlists/whitelist.txt "
              "--hostlist=hostlists/UDP_YT_List.txt "
              "--filter-udp=443 --filter-l7=quic")
    return f"{prefix} {s} --new"


def build_discord_udp() -> str:
    s = parse_quic_ini("discord_voice_autocircular")
    s = ensure_circular_nld2(s)
    s = strip_dead_range_args(s)
    return f"{s} --new"


def build_stun() -> str:
    # config_official.sh:1319 — STUN catch-all for general WebRTC discovery.
    return "--filter-udp=1024-65535 --filter-l7=stun --in-range=a --out-range=-n4 --new"


def build_http_rkn() -> str:
    """HTTP RKN — inline in config_official.sh:1601, not in strats_new2.txt.
    Verbatim transcription with hostlist paths adapted to z2w layout."""
    return (
        "--filter-tcp=80 "
        "--hostlist-exclude=hostlists/whitelist.txt "
        "--hostlist=hostlists/TCP_RKN_List.txt "
        "--hostlist=hostlists/extra-domains.txt "
        "--in-range=-s5556 "
        "--payload=http_req,empty,http_reply "
        "--lua-desync=circular:fails=2:time=60:reset:key=http_rkn:nld=2"
            ":failure_detector=z2k_silent_drop_detector"
            ":success_detector=z2k_http_success_positive_only"
            ":no_http_redirect "
        "--lua-desync=http_methodeol:payload=http_req:dir=out:strategy=1 "
        "--lua-desync=syndata:payload=http_req:dir=out:strategy=2 "
        "--lua-desync=multisplit:payload=http_req:dir=out:strategy=2 "
        "--lua-desync=hostfakesplit:payload=http_req:dir=out:ip_ttl=2:repeats=1:strategy=3 "
        "--lua-desync=fake:payload=http_req:dir=out:blob=fake_default_http:badsum:repeats=1:strategy=4 "
        "--lua-desync=fakedsplit:payload=http_req:dir=out:pos=method+2:badsum:strategy=5 "
        "--lua-desync=fake:payload=http_req:dir=out:blob=0x0E0E0F0E:tcp_md5:strategy=6 "
        "--lua-desync=multisplit:payload=http_req:dir=out:pos=host+1:seqovl=2:strategy=6 "
        "--lua-desync=fake:payload=http_req:dir=out:blob=fake_default_http:badsum:repeats=1:strategy=7 "
        "--lua-desync=multisplit:payload=http_req:dir=out:pos=method+2:strategy=7 "
        "--lua-desync=z2k_http_methodeol_safe:payload=http_req:dir=out:strategy=8 "
        "--lua-desync=z2k_http_xpadding:payload=http_req:dir=out:strategy=9 "
        "--lua-desync=z2k_http_inject_safe_header:payload=http_req:dir=out:strategy=10 "
        "--lua-desync=z2k_http_simple_bypass:payload=http_req:dir=out:strategy=11 "
        "--lua-desync=z2k_http_lf_prefix:payload=http_req:dir=out:strategy=12 "
        "--lua-desync=z2k_http_space_prefix:payload=http_req:dir=out:strategy=13 "
        "--lua-desync=z2k_http_tab_prefix:payload=http_req:dir=out:strategy=14 "
        "--lua-desync=z2k_http_multi_crlf:payload=http_req:dir=out:strategy=15 "
        "--lua-desync=z2k_http_mixed_prefix:payload=http_req:dir=out:strategy=16 "
        "--lua-desync=z2k_http_garbage_prefix:payload=http_req:dir=out:strategy=17 "
        "--lua-desync=z2k_http_hostmod:payload=http_req:dir=out:strategy=18 "
        "--lua-desync=z2k_http_method_obfuscate:payload=http_req:dir=out:strategy=19 "
        "--lua-desync=z2k_http_version_downgrade:payload=http_req:dir=out:strategy=20 "
        "--lua-desync=z2k_http_oob_prefix:payload=http_req:dir=out:strategy=21 "
        "--lua-desync=z2k_http_absolute_url:payload=http_req:dir=out:strategy=22 "
        "--lua-desync=z2k_http_absolute_uri_v2:payload=http_req:dir=out:strategy=23 "
        "--lua-desync=z2k_http_methodeol_v2:payload=http_req:dir=out:strategy=24 "
        "--lua-desync=z2k_http_methodeol_hostcase:payload=http_req:dir=out:strategy=25 "
        "--lua-desync=z2k_http_pipeline_fake:payload=http_req:dir=out:strategy=26 "
        "--lua-desync=z2k_http_pipeline_fake_v2:payload=http_req:dir=out:strategy=27 "
        "--lua-desync=z2k_http_fake_continuation:payload=http_req:dir=out:strategy=28 "
        "--lua-desync=z2k_http_fake_xhost:payload=http_req:dir=out:strategy=29 "
        "--lua-desync=z2k_http_header_shuffle:payload=http_req:dir=out:strategy=30 "
        "--lua-desync=z2k_http_host_bytesplit:payload=http_req:dir=out:strategy=31 "
        "--lua-desync=z2k_http_seqovl_host:payload=http_req:dir=out:strategy=32 "
        "--lua-desync=z2k_http_triple_seqovl:payload=http_req:dir=out:strategy=33 "
        "--lua-desync=z2k_http_mgts_combo:payload=http_req:dir=out:strategy=34 "
        "--lua-desync=z2k_http_combo_bypass:payload=http_req:dir=out:strategy=35 "
        "--lua-desync=z2k_http_super_decoy:payload=http_req:dir=out:strategy=36 "
        "--lua-desync=z2k_http_multidisorder:payload=http_req:dir=out:strategy=37 "
        "--lua-desync=z2k_http_ipfrag:payload=http_req:dir=out:strategy=38 "
        "--lua-desync=z2k_http_syndata:payload=http_req:dir=out:strategy=39 "
        "--lua-desync=z2k_http_aggressive:payload=http_req:dir=out:strategy=40 "
        "--in-range=x --new"
    )


# ─── Driver ─────────────────────────────────────────────────────────────────────

PROFILES = [
    ("rkn_tcp",     build_rkn_tcp),
    ("yt_tcp",      build_yt_tcp),
    ("gv_tcp",      build_gv_tcp),
    ("yt_quic",     build_yt_quic),
    ("discord_udp", build_discord_udp),
    ("stun",        build_stun),
    ("http_rkn",    build_http_rkn),
]

HEADER = (
    "# AUTO-GENERATED by tools/build_profiles.py — DO NOT EDIT BY HAND\n"
    "# Sources: vendor/z2k/strats_new2.txt + vendor/z2k/quic_strats.ini\n"
    "# Re-run after syncing those files from upstream necronicle/z2k.\n"
)


# ─── Runtime config-size guard ────────────────────────────────────────────────
# z2w starts winws2 via `winws2.exe @cache/winws2.conf`. The conf file is
# generated at runtime as BASE_ARGS + one profile per line of this output,
# shell-quoted (one token per line). winws2's config_from_file() loads it
# into a static char buf[MAX_CONFIG_FILE_SIZE] minus 3 bytes preamble.
#
# Fork necronicle/zapret2-z2k v0.9.5.2-z2k-r3 bumped MAX_CONFIG_FILE_SIZE
# from 16384 → 65536. We guard here so a future z2k sync that blows past
# 65533 - BASE_ARGS_RESERVE fails CI immediately instead of producing a
# z2w build that silently truncates strategies mid-token at first launch.
WINWS_CONF_CAP    = 65536 - 3
BASE_ARGS_RESERVE = 2048   # generous: actual BASE_ARGS today ≈ 1400 bytes


def _simulated_runtime_config_size(profile_lines: list[str]) -> int:
    """Estimate `cache/winws2.conf` size for the upcoming runtime invocation.
    Mirrors _write_winws_config() in z2k_gui.py: each token shell-quoted on
    its own line. We approximate via raw byte count + 1 for newline since
    our profile args don't contain chars shlex.quote() needs to escape (no
    spaces, quotes, $/`/backslashes); the rare exception (<5 bytes per
    string) is dwarfed by BASE_ARGS_RESERVE."""
    # Each profile line is multiple space-separated tokens that become
    # one-token-per-line in the conf. Total bytes ≈ same count: spaces
    # become newlines, no change in length.
    profile_bytes = sum(len(line) + 1 for line in profile_lines)
    return profile_bytes + BASE_ARGS_RESERVE


def main() -> None:
    out_lines: list[str] = []
    for name, fn in PROFILES:
        line = fn()
        n_strats = len(set(re.findall(r":strategy=(\d+)", line))) or "—"
        print(f"  {name:12s}  strategies={n_strats:>3}  len={len(line)}")
        out_lines.append(line)
    OUTPUT.write_text(HEADER + "\n".join(out_lines) + "\n", encoding="utf-8")
    print(f"\nWrote {OUTPUT}  ({len(out_lines)} profiles)")

    # Fail loud if we're close to the fork's MAX_CONFIG_FILE_SIZE.
    sim = _simulated_runtime_config_size(out_lines)
    headroom = WINWS_CONF_CAP - sim
    pct = 100.0 * sim / WINWS_CONF_CAP
    print(f"\nRuntime config size: ~{sim} B  /  cap {WINWS_CONF_CAP} B  "
          f"({pct:.1f}% used, {headroom} B headroom)")
    if sim > WINWS_CONF_CAP:
        raise SystemExit(
            f"\nFATAL: estimated runtime config {sim} B exceeds fork cap "
            f"{WINWS_CONF_CAP} B. Bump MAX_CONFIG_FILE_SIZE in fork "
            f"necronicle/zapret2-z2k nfq2/nfqws.c and rebuild winws2.exe."
        )


if __name__ == "__main__":
    main()
