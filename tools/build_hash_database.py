#!/usr/bin/env python3
"""
build_hash_database.py  (v2 -- detection-aware architecture)

HashFox offline hash database generator.

Builds database/hashes.json from:
  - tools/raw_hashcat_modes.py  (RAW_MODES, ALIASES -- verbatim from the
    official hashcat "Example Hashes" wiki: https://hashcat.net/wiki/doku.php?id=example_hashes)
  - tools/enrichment.py         (ENRICHMENT -- hand-verified metadata for
    well-documented formats)

No network access anywhere in this script. HashFox must work fully offline.

v2 changes vs the first version:
  - hashcat_mode is no longer treated as a 1:1 proxy for a unique detectable
    signature. Wiki rows that share a mode number are preserved as
    "variants" on the canonical record instead of being discarded.
  - "aliases" (hand-curated, from raw_hashcat_modes.ALIASES) carry alternate
    product/tool names for the same underlying format.
  - Structural detection hints (prefixes, separators, length, character_set)
    are filled in two ways:
      1. explicit, hand-verified values from enrichment.py (highest trust)
      2. mechanically DERIVED (not guessed) from the verified example_hash
         string itself -- e.g. a hash starting "$6$" gets prefix "$6$";
         a pure-hex string gets character_set "hex" and its exact length.
         This is parsing of already-verified data, not invention.
  - "salted" is set from enrichment.py, or inferred only from the wiki's own
    algorithmic naming convention (e.g. "sha1($pass.$salt)" clearly names
    itself as salted; "SHA1" alone is documented as unsalted). Anything not
    covered by one of those two sources stays null.
  - "detection_quality" is computed (high/medium/low/reference_only) from
    how much structural signal a record actually has, so HashFox's detector
    never has to pretend it can reliably fingerprint all ~280 modes.
  - "category" is auto-assigned via conservative keyword matching against
    the hashcat-provided name when enrichment.py didn't already set one,
    falling back to "other" (never left as an unlabeled bucket).

Usage:
    python3 tools/build_hash_database.py [--output PATH] [--check-only] [--verbose]
"""

import argparse
import json
import os
import re
import sys
from collections import OrderedDict, Counter

from raw_hashcat_modes import RAW_MODES, ALIASES
from enrichment import ENRICHMENT

SCHEMA_FIELDS = [
    "name",
    "aliases",
    "variants",
    "category",
    "hashcat_mode",
    "john_format",
    "length",
    "min_length",
    "max_length",
    "character_set",
    "regex",
    "prefixes",
    "separators",
    "salted",
    "example_hash",
    "detection_quality",
    "security_level",
    "description",
    "common_usage",
    "recommended_attack",
    "recommended_wordlists",
    "hashcat_supported",
    "john_supported",
]

DEFAULT_RECORD = {
    "name": None,
    "aliases": [],
    "variants": [],
    "category": None,
    "hashcat_mode": None,
    "john_format": None,
    "length": None,
    "min_length": None,
    "max_length": None,
    "character_set": None,
    "regex": None,
    "prefixes": [],
    "separators": [],
    "salted": None,
    "example_hash": None,
    "detection_quality": None,
    "security_level": None,
    "description": None,
    "common_usage": [],
    "recommended_attack": [],
    "recommended_wordlists": [],
    "hashcat_supported": True,
    "john_supported": False,
}

HEX_RE = re.compile(r"^[a-fA-F0-9]+$")

# Ordered, conservative keyword -> category rules. Applied only when
# enrichment.py did not already set an explicit category. First match wins.
CATEGORY_RULES = [
    (("kerberos", "krb5"), "kerberos"),
    (("cisco", "fortigate", "juniper", "netscaler"), "network_device"),
    (("mysql", "postgres", "oracle", "sybase", "389-ds", "ldap", "prestashop", "opencart"), "database"),
    (("wpa-", "wpa2", "pmkid",), "wireless"),
    (("truecrypt", "veracrypt", "luks", "filevault", "diskcryptor", "apfs", "bitlocker", "ecryptfs", "dpapi"), "disk_encryption"),
    (("bitcoin", "litecoin", "ethereum", "electrum", "wallet.dat"), "cryptocurrency"),
    (("ms office", "oldoffice", "office 2007", "office 2010", "office 2013"), "office_document"),
    (("pdf", "odf", "open document"), "document"),
    (("rar3", "rar5", "7-zip", "pkzip", "winzip", "\\bzip\\b"), "archive"),
    (("wordpress", "drupal", "joomla", "phpbb", "django"), "cms"),
    (("aix {", "qnx", "bsdi", "descrypt", "md5crypt", "sha256crypt", "sha512crypt", "des (unix)", "unix)"), "unix"),
    (("windows phone", "domain cached credentials", "ms cache", "\\blm\\b", "\\bntlm\\b", "netntlm"), "windows"),
    (("hmac",), "hmac"),
    (("pbkdf2", "bcrypt", "scrypt", "argon2"), "kdf"),
    (("sip digest", "ike-psk", "tacacs", "radius", "ipmi", "cram-md5", "dovecot"), "network_protocol"),
    (("1password", "lastpass", "keepass", "password safe", "ansible vault", "gpg (", "jks java key store", "apple secure notes", "radmin"), "application"),
    (("wallet, my wallet", "blockchain, my wallet"), "cryptocurrency"),
]


def matches_any(name_lower, keywords):
    for kw in keywords:
        if kw.startswith("\\b"):
            if re.search(kw, name_lower):
                return True
        elif kw in name_lower:
            return True
    return False


def auto_categorize(name):
    lname = name.lower()
    for keywords, category in CATEGORY_RULES:
        if matches_any(lname, keywords):
            return category
    if re.search(r"\b(sha\d|md\d|ripemd|whirlpool|gost|keccak|blake2|crc32|hashcode)\b", lname):
        if "$salt" in lname or "hmac" in lname:
            return "salted_hash"
        return "raw_hash"
    if "$salt" in lname or ("$pass" in lname and "salt" in lname):
        return "salted_hash"
    return "other"


KNOWN_UNSALTED_RAW_NAMES = {
    "md5", "sha1", "md4", "ntlm", "lm", "half md5", "crc32", "ripemd-160", "whirlpool",
    "sha2-224", "sha2-256", "sha2-384", "sha2-512",
    "sha3-224", "sha3-256", "sha3-384", "sha3-512",
    "keccak-224", "keccak-256", "keccak-384", "keccak-512",
    "gost r 34.11-94", "mysql323", "java object hashcode()",
    "gost r 34.11-2012 (streebog) 256-bit, big-endian",
    "gost r 34.11-2012 (streebog) 512-bit, big-endian",
    "blake2b-512",
}


def infer_salted_from_name(name, current):
    """
    Only infer when the wiki's own naming convention makes it unambiguous:
    formats explicitly written as f($pass, $salt) combinations, HMAC
    constructions (keyed), or formats the wiki lists as bare/unsalted
    algorithm names. Everything else is left as None (unknown) rather than
    guessed.
    """
    if current is not None:
        return current
    lname = name.lower()
    if "hmac" in lname:
        return True
    if "$salt" in lname:
        return True
    if lname in KNOWN_UNSALTED_RAW_NAMES:
        return False
    return None


def extract_prefix(example):
    """
    Mechanically derive a literal prefix marker from an already-verified
    example hash string. This is parsing, not invention: the prefix is
    exactly what's present in the wiki's own example. Returns None if no
    clean delimiter-bounded prefix is found.
    """
    if not example:
        return None
    if example.startswith("{"):
        end = example.find("}")
        if end != -1:
            return example[:end + 1]
    if example.startswith("@"):
        idxs = [i for i, c in enumerate(example) if c == "@"]
        if len(idxs) >= 2:
            return example[:idxs[1] + 1]
    if example.startswith("$"):
        idxs = [i for i, c in enumerate(example) if c == "$"]
        if len(idxs) >= 2:
            return example[:idxs[1] + 1]
        if len(idxs) == 1:
            return example[:idxs[0] + 1]
    return None


def auto_infer_structure(record):
    """
    Fill in weak/derived structural hints ONLY where enrichment.py left the
    field empty. Never overrides hand-verified data. Source of truth is
    always the verified example_hash string or the verified wiki name --
    nothing here is fabricated.
    """
    example = record["example_hash"]

    if example:
        core = example.split(":")[0]
        if HEX_RE.match(core) and not record["character_set"]:
            record["character_set"] = "hex"
            if record["length"] is None and record["min_length"] is None:
                record["length"] = len(core)
                record["min_length"] = len(core)
                record["max_length"] = len(core)

        if ":" in example and not record["separators"]:
            record["separators"] = [":"]

        if not record["prefixes"]:
            prefix = extract_prefix(example)
            if prefix:
                record["prefixes"] = [prefix]

    record["salted"] = infer_salted_from_name(record["name"], record["salted"])


def compute_detection_quality(record):
    """
    high            : has a distinctive literal prefix (e.g. "$6$", "$2a$",
                       "$krb5tgs$23$", "{smd5}") -- the string announces its
                       own format, so it's reliably fingerprintable even
                       against a huge candidate pool.
    medium          : no distinctive prefix, but there's still a real
                       structural constraint -- either a verified regex, or
                       a known length + character set together (e.g. plain
                       32-char hex). This is deliberately NOT "high": a bare
                       32-hex-char regex matches MD5, NTLM, and MD4 equally
                       well, so on its own it narrows the field rather than
                       identifying it. The scoring engine is expected to
                       return multiple candidates for these.
    low             : only one weak signal (length OR character set alone,
                       not both, and no regex/prefix).
    reference_only  : mode is known from hashcat, but there isn't enough
                       structural data here for automatic identification.
    """
    has_prefix = bool(record["prefixes"])
    has_regex = bool(record["regex"])
    has_length = record["length"] is not None or record["min_length"] is not None
    has_charset = bool(record["character_set"])

    if has_prefix:
        return "high"
    if has_regex or (has_length and has_charset):
        return "medium"
    if has_length or has_charset:
        return "low"
    return "reference_only"


class ValidationIssue:
    def __init__(self, level, mode, message):
        self.level = level  # "error" | "warning"
        self.mode = mode
        self.message = message

    def __str__(self):
        tag = "ERROR" if self.level == "error" else "WARN"
        mode_str = f"[mode {self.mode}]" if self.mode is not None else ""
        return f"{tag} {mode_str} {self.message}"


def build_records(raw_modes, enrichment, aliases_table):
    issues = []
    records_by_mode = OrderedDict()
    mode_counts = Counter(m for m, _, _ in raw_modes)
    duplicate_rows_collapsed = 0

    for mode, name, example in raw_modes:
        if not name or not str(name).strip():
            issues.append(ValidationIssue("error", mode, "missing/empty name"))
            name = name or None

        if example is not None and not str(example).strip():
            issues.append(ValidationIssue("warning", mode, "example_hash present but empty string; normalized to null"))
            example = None

        if mode in records_by_mode:
            # A second (or later) wiki row for a mode we've already seen.
            # Preserve it as a variant instead of discarding it.
            duplicate_rows_collapsed += 1
            canonical = records_by_mode[mode]
            if name and name != canonical["name"] and name not in canonical["variants"]:
                canonical["variants"].append(name)
            issues.append(ValidationIssue(
                "warning", mode,
                f"additional wiki row '{name}' for this mode preserved as a variant "
                f"(canonical name stays '{canonical['name']}')"
            ))
            continue

        if example is None:
            issues.append(ValidationIssue(
                "warning", mode,
                "no plain-text example hash available (binary/container format, "
                "or wiki lists only a downloadable file) -- example_hash set to null"
            ))

        record = dict(DEFAULT_RECORD)
        record["name"] = name
        record["hashcat_mode"] = mode
        record["example_hash"] = example
        record["aliases"] = list(aliases_table.get(mode, []))
        record["variants"] = []

        extra = enrichment.get(mode)
        if extra:
            for key, value in extra.items():
                if key not in SCHEMA_FIELDS:
                    issues.append(ValidationIssue("warning", mode, f"enrichment.py has unknown field '{key}' -- ignored"))
                    continue
                record[key] = value
            if extra.get("aliases"):
                merged = list(dict.fromkeys(record["aliases"] + extra["aliases"]))
                record["aliases"] = merged
            if extra.get("john_format"):
                record["john_supported"] = True

        records_by_mode[mode] = record

    records = []
    for mode, record in records_by_mode.items():
        if record["category"] is None:
            record["category"] = auto_categorize(record["name"] or "")
        auto_infer_structure(record)
        record["detection_quality"] = compute_detection_quality(record)
        ordered = OrderedDict((field, record[field]) for field in SCHEMA_FIELDS)
        records.append(ordered)

    if duplicate_rows_collapsed:
        issues.append(ValidationIssue(
            "warning", None,
            f"{duplicate_rows_collapsed} duplicate wiki row(s) across all modes were "
            f"collapsed into 'variants' rather than discarded"
        ))

    return records, issues


def validate_records(records):
    issues = []
    modes_seen = Counter(r["hashcat_mode"] for r in records)
    for mode, count in modes_seen.items():
        if count > 1:
            issues.append(ValidationIssue("error", mode, f"duplicate hashcat_mode survived dedup ({count}x)"))

    for r in records:
        if r["hashcat_mode"] is None:
            issues.append(ValidationIssue("error", None, f"record '{r['name']}' has no hashcat_mode"))
        if not r["name"]:
            issues.append(ValidationIssue("error", r["hashcat_mode"], "record has missing name"))
        missing_fields = [f for f in SCHEMA_FIELDS if f not in r]
        if missing_fields:
            issues.append(ValidationIssue("error", r["hashcat_mode"], f"record missing schema fields: {missing_fields}"))
        if r["john_supported"] and not r["john_format"]:
            issues.append(ValidationIssue("error", r["hashcat_mode"], "john_supported=true but john_format is null"))
        if r["john_format"] and not r["john_supported"]:
            issues.append(ValidationIssue("error", r["hashcat_mode"], "john_format set but john_supported=false"))

    return issues


def validate_json_roundtrip(data):
    try:
        text = json.dumps(data, ensure_ascii=False)
        json.loads(text)
        return True, None
    except (TypeError, ValueError) as exc:
        return False, str(exc)


def print_summary(records, issues, raw_modes):
    total = len(records)
    total_raw_rows = len(raw_modes)
    with_examples = sum(1 for r in records if r["example_hash"])
    with_john = sum(1 for r in records if r["john_format"])
    with_regex = sum(1 for r in records if r["regex"])
    with_prefix = sum(1 for r in records if r["prefixes"])
    with_length = sum(1 for r in records if r["length"] is not None or r["min_length"] is not None)
    with_aliases = sum(1 for r in records if r["aliases"])
    with_variants = sum(1 for r in records if r["variants"])
    categories = Counter(r["category"] for r in records)
    quality = Counter(r["detection_quality"] for r in records)

    errors = [i for i in issues if i.level == "error"]
    warnings = [i for i in issues if i.level == "warning"]

    print("=" * 64)
    print("HashFox Hash Database - Build Summary (v2)")
    print("=" * 64)
    print(f"Total raw wiki rows parsed:    {total_raw_rows}")
    print(f"Total format records (modes):  {total}")
    print(f"Entries with examples:         {with_examples}")
    print(f"Entries with John formats:     {with_john}")
    print(f"Entries with regex:            {with_regex}")
    print(f"Entries with prefix hints:     {with_prefix}")
    print(f"Entries with length info:      {with_length}")
    print(f"Entries with aliases:          {with_aliases}")
    print(f"Entries with variants:         {with_variants}")
    print(f"Validation errors:             {len(errors)}")
    print(f"Validation warnings:           {len(warnings)}")
    print()
    print("Detection quality distribution:")
    for level in ("high", "medium", "low", "reference_only"):
        print(f"  - {level:<15} {quality.get(level, 0)}")
    print()
    print("Categories:")
    for cat, count in sorted(categories.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  - {cat:<20} {count}")
    print("=" * 64)

    cannot_detect = quality.get("reference_only", 0)
    print(f"\nRecords that cannot participate in automatic detection "
          f"(reference_only): {cannot_detect} / {total}")

    if errors:
        print("\nERRORS (must fix before shipping database/hashes.json):")
        for e in errors:
            print(f"  {e}")

    if warnings:
        print(f"\n{len(warnings)} warnings (informational). Most are expected: "
              f"duplicate wiki rows collapsed into 'variants', and container/binary "
              f"formats with no plain-text example.")


def main():
    parser = argparse.ArgumentParser(description="Build the HashFox offline hash database.")
    parser.add_argument(
        "--output",
        default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "database", "hashes.json"),
        help="Output path for hashes.json (default: ../database/hashes.json relative to this script)",
    )
    parser.add_argument("--check-only", action="store_true", help="Validate and print summary but do not write output.")
    parser.add_argument("--verbose", action="store_true", help="Print every validation issue, not just errors.")
    args = parser.parse_args()

    records, build_issues = build_records(RAW_MODES, ENRICHMENT, ALIASES)
    records.sort(key=lambda r: r["hashcat_mode"])

    post_issues = validate_records(records)
    all_issues = build_issues + post_issues

    if args.verbose:
        for issue in all_issues:
            print(issue)

    ok, err = validate_json_roundtrip(records)
    if not ok:
        print(f"FATAL: generated data is not valid JSON: {err}", file=sys.stderr)
        sys.exit(1)

    fatal_errors = [i for i in all_issues if i.level == "error"]

    print_summary(records, all_issues, RAW_MODES)

    if fatal_errors:
        print(f"\n{len(fatal_errors)} fatal validation error(s) found. Not writing output.", file=sys.stderr)
        sys.exit(1)

    if args.check_only:
        print("\n--check-only set: skipping write.")
        sys.exit(0)

    out_dir = os.path.dirname(args.output)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2, sort_keys=False)
        f.write("\n")

    print(f"\nWrote {len(records)} entries to {args.output}")


if __name__ == "__main__":
    main()
