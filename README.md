<div align="center">

```
  ____ ___ ____  _   _ _____ ____      _   _   _ ____ ___ _____
 / ___|_ _|  _ \| | | | ____|  _ \    / \ | | | |  _ \_ _|_   _|
| |    | || |_) | |_| |  _| | |_) |  / _ \| | | | | | | |  | |
| |___ | ||  __/|  _  | |___|  _ <  / ___ \ |_| | |_| | |  | |
 \____|___|_|   |_| |_|_____|_| \_\/_/   \_\___/|____/___| |_|
```

### ✦ TLS Certificate & Protocol Security Inspector ✦

**Reads what the handshake reveals. No MITM, no exploitation.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Made by Mindless](https://img.shields.io/badge/Made%20by-Mindless-ff69b4.svg)](https://linxploit.com/founder)
[![Linxploit](https://img.shields.io/badge/Linxploit-linxploit.com-black.svg)](https://linxploit.com)

**Made by [Mindless](https://linxploit.com/founder) — Founder & CEO of [Linxploit](https://linxploit.com)**

</div>

---

## 🧠 What is CipherAudit?

**CipherAudit** connects to a host over TLS — the same handshake any browser performs — and reports back what the certificate actually says, which protocol versions the server negotiates, and whether a handful of HTTPS security headers are present.

It's built to answer the questions that come up constantly around TLS hygiene: *Is this cert about to expire? Is it self-signed or untrusted? Is the key strong enough? Does the server still accept TLS 1.0? Is HSTS actually turned on?*

---

## 🐛 Why this exists (a real bug worth knowing about)

A common mistake in hand-rolled TLS inspection scripts — including an earlier internal tool this one replaced — is calling `ssl.getpeercert()` after disabling certificate verification (`verify_mode = ssl.CERT_NONE`). **Python's `ssl` module only populates the parsed certificate dictionary when verification actually runs.** With verification off, `getpeercert()` silently returns `{}` — every single time, for every certificate, regardless of the target. The subject, issuer, validity dates: all silently empty, with no error raised.

CipherAudit fixes this properly: it retrieves the raw certificate bytes (which are available regardless of verification mode) and parses them directly with the `cryptography` library. It then performs a **separate**, real verifying handshake to determine actual trust-store validation — so you get full certificate detail *and* an accurate trust verdict, even for self-signed or expired certificates.

---

## ✨ Features

- 🎨 **Clean, structured terminal report** — certificate summary, protocol support table, HTTPS security headers, and severity-ranked findings.
- 🔐 **Correct certificate parsing** (see above) — subject, issuer, SAN list, validity window, serial number, key type/size, signature algorithm, and both SHA-1/SHA-256 fingerprints, extracted directly from the DER-encoded certificate.
- ✅ **Independent trust validation** — a second handshake against the system trust store reports whether the cert is actually trusted, separate from the raw parse.
- 🔑 **Key & signature strength checks** — flags RSA keys under 2048 bits and weak signature algorithms (SHA-1/MD5).
- 📡 **Honest legacy-protocol testing** — modern OpenSSL builds block SSLv3/TLSv1.0/TLSv1.1 at the client's security-policy level, independent of what the server supports. CipherAudit detects this and reports **INCONCLUSIVE** rather than a false "not supported," and lowers the client's security level where possible to get a real answer from the server instead of a client-side refusal.
- 🌐 **HTTPS security header check** — HSTS, CSP, X-Frame-Options, and more, layered into the same report.
- ⚡ **Concurrent multi-host scanning**, custom ports via `host:port` syntax, `--skip-legacy` for faster scans.
- 📊 **Exportable JSON report** with every field and finding.
- 🛡️ **Authorization gate** — confirms you're allowed to assess a target before opening any connection (skippable with `--yes`).

---

## 📸 Preview

```
✦ TLS Certificate & Protocol Security Inspector ✦

[ TARGET: example.com:443 ]
────────────────────────────────────────────────────────────
  Certificate
    • Subject : example.com
    • Issuer  : CN=Let's Encrypt Authority
    • Valid   : 2026-06-01 → 2026-08-30  [17d remaining]
    • Key     : RSA 2048-bit, signature sha256
    • Trust   : trusted by system store

  Protocol Support
    ? SSLv3     inconclusive  Inconclusive — local OpenSSL policy blocks this protocol...
    • TLSv1.0   not supported  Server rejected this protocol version.
    • TLSv1.1   not supported  Server rejected this protocol version.
    ✔ TLSv1.2   supported  Negotiated TLSv1.2
    ✔ TLSv1.3   supported  Negotiated TLSv1.3

  Findings
    [HIGH] Certificate expires in 17 day(s).
    [MEDIUM] HSTS (Strict-Transport-Security) header is missing.
```

---

## 📦 Installation

```bash
git clone https://github.com/linxploit/cipher-audit.git
cd cipher-audit
pip install -r requirements.txt
```

Requires **Python 3.8+**. The `cryptography` package is required for certificate parsing.

---

## 🚀 Usage

### Inspect a single host

```bash
python3 cipheraudit.py -H example.com
```

### Inspect a non-standard port

```bash
python3 cipheraudit.py -H example.com:8443
```

### Skip legacy protocol probing (faster, avoids inconclusive results)

```bash
python3 cipheraudit.py -H example.com --skip-legacy
```

### Inspect a list of hosts

```bash
python3 cipheraudit.py -l examples/hosts.txt --threads 3
```

### See the certificate fingerprint and serial number

```bash
python3 cipheraudit.py -H example.com -v
```

### Save a report

```bash
python3 cipheraudit.py -l examples/hosts.txt -o report.json
```

### Full option reference

```bash
python3 cipheraudit.py --help
```

| Flag | Description |
|---|---|
| `-H`, `--host` | Target host, optionally `host:port` (default port 443) |
| `-l`, `--list` | File with one host per line |
| `-t`, `--timeout` | Per-connection timeout in seconds (default: `8`) |
| `--threads` | Concurrent targets scanned in parallel (default: `3`) |
| `--skip-legacy` | Skip SSLv3/TLSv1.0/TLSv1.1 probing entirely |
| `--no-headers` | Skip the HTTPS security header check |
| `-o`, `--output` | Save report to a JSON file |
| `-v`, `--verbose` | Show fingerprint and serial number |
| `--yes` | Skip the authorization confirmation prompt |
| `--no-banner` | Suppress the ASCII banner |
| `--version` | Print version info and exit |

---

## 🧭 A note on legacy protocol testing

You'll sometimes see `SSLv3`, and occasionally `TLSv1.0`/`TLSv1.1`, reported as **INCONCLUSIVE** instead of a clear yes/no. This isn't a bug — it reflects a real limitation of testing legacy protocols from a modern machine: OpenSSL 3.0+ disables these protocols at its own security-policy level by default, which can block the *client* from even attempting the handshake, regardless of what the server would accept. CipherAudit lowers its own security level where possible to get a real answer from the server rather than a client-side refusal, and clearly labels the result when it still can't get a definitive one. For authoritative legacy-protocol auditing, pair this with a dedicated tool like `testssl.sh` or the Qualys SSL Labs service.

---

## ⚖️ Responsible use

CipherAudit opens a handful of TLS connections per target (one per protocol version tested, plus certificate retrieval and an HTTPS header check) — nothing beyond what a browser or standard TLS scanner does. Still:

- Only run CipherAudit against hosts you **own** or have **explicit permission** to assess.
- CipherAudit will ask you to confirm authorization before scanning, every time, unless you pass `--yes`.
- You are solely responsible for how you use this tool and for complying with all applicable laws and the terms of any authorization you've been granted.

---

## 🛠️ Project structure

```
cipher-audit/
├── cipheraudit.py         # Main executable — the tool itself
├── requirements.txt          # Python dependencies
├── examples/
│   └── hosts.txt                # Example host list for -l/--list
├── tests/
│   └── test_cipheraudit.py      # Unit tests (plus a live integration test)
├── LICENSE                    # MIT License
└── README.md                   # You are here
```

---

## 🤝 Contributing

Issues and pull requests are welcome — additional cipher-suite inspection, OCSP/CRL revocation checks, and certificate chain validation are all great directions to extend this in.

---

## 📜 License

Released under the [MIT License](LICENSE).

---

<div align="center">

### Made by **Mindless**
**Founder & CEO of [Linxploit](https://linxploit.com)**

🌐 [linxploit.com](https://linxploit.com) &nbsp;·&nbsp; 👤 [linxploit.com/founder](https://linxploit.com/founder)

</div>
