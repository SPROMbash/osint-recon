# osint-recon

Asynchronous OSINT aggregator for **domains and organisations**. Give it a domain
and it gathers **public** information from several sources concurrently
(subdomains, emails, technologies, document metadata and known data breaches),
then consolidates everything into a Markdown and a JSON report. It can also
review **your own digital footprint**.

```bash
osint-recon domain example.com --passive-only     # third-party sources only
osint-recon domain example.com --authorized       # + crawl, documents, DNS
osint-recon footprint                             # your own emails in HIBP
```

> [!IMPORTANT]
> **Ethical scope.** Use osint-recon only on domains and organisations you are
> **authorised to assess** (your own, or a client's under a signed engagement),
> or to review **your own exposure**. It is not a people-search tool and is
> designed so it cannot be used as one (see [Ethical safeguards](#ethical-safeguards)).
> Reports contain personal data: store them securely and delete them when done.

---

## Contents

- [What it collects](#what-it-collects)
- [Ethical safeguards](#ethical-safeguards)
- [Installation](#installation)
- [Usage](#usage)
- [API keys](#api-keys)
- [Configuration](#configuration)
- [Reports](#reports)
- [Exit codes](#exit-codes)
- [Development](#development)
- [Architecture](#architecture)
- [What this project demonstrates](#what-this-project-demonstrates)
- [License](#license)

## What it collects

| Data | Source | Type | Key |
|---|---|---|---|
| Subdomains | [crt.sh](https://crt.sh) Certificate Transparency logs | passive | no |
| Subdomains + IPs | [HackerTarget](https://hackertarget.com) hostsearch (50/day free) | passive | no |
| Subdomains + IPs | [AlienVault OTX](https://otx.alienvault.com) passive DNS | passive | optional |
| Emails, names, positions | [Hunter.io](https://hunter.io) domain search (25/month free) | passive | **yes** |
| Breaches of the domain's service | [Have I Been Pwned](https://haveibeenpwned.com) `/breaches?domain=` | passive | no |
| Domain accounts in breaches | HIBP `/breacheddomain` (**verified domains only**) | passive | **yes** |
| Live subdomains | DNS resolution, with wildcard detection | **active** | no |
| Technologies, emails, document links | Polite crawl of the website | **active** | no |
| Document metadata (authors, software, dates) | Public PDF / DOCX / XLSX / PPTX | **active** | no |

*Passive* sources query third parties and never touch the target. *Active*
sources contact the target's own servers.

Search engines (Google, Bing) are deliberately **not** scraped: their terms of
service forbid it. Documents are discovered by crawling the site itself.

## Ethical safeguards

These are enforced **in code**, with tests that prove them:

| Safeguard | How |
|---|---|
| **Active collection needs authorisation** | Crawling, downloading documents and resolving DNS only run if the domain is in `scope` in your config or you pass `--authorized`. Otherwise the tool refuses (exit code 4) and suggests `--passive-only`. |
| **No per-person breach lookups** | Emails found during a scan are **never** looked up in HIBP. Per-account data comes only from `/breacheddomain`, which HIBP itself only answers for domains **you have verified**. |
| **Your footprint is yours** | `footprint` only checks the `owned_emails` listed in *your* config. |
| **No profiling** | Names and emails only come from sources tied to the domain (Hunter, the website, document metadata). No social networks, no cross-referencing of a person across sources. |
| **Sharing safely** | `--redact-people` masks emails (`j***@example.com`) and names (`J. S.`) in the reports. |
| **Respect for sites and APIs** | `robots.txt` is honoured (and a `5xx` on it means *do not crawl*, as RFC 9309 says), crawl depth and page limits, honest User-Agent, per-source rate limits that follow each service's published limits, `Retry-After` honoured. |
| **Secrets never leak** | API keys are read from environment variables and masked as `***` in the console and log file, even inside error messages that contain URLs. |

## Installation

Python 3.10+, on Linux (Kali, Parrot...), macOS or Windows. No external tools
are needed: everything is HTTP and DNS from Python.

```bash
# as a CLI tool (recommended)
pipx install git+https://github.com/SPROMbash/osint-recon.git

# for development
git clone https://github.com/SPROMbash/osint-recon.git
cd osint-recon
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
osint-recon --help
```

## Usage

```bash
# Which sources are ready (keys, config)?
osint-recon sources

# See the plan first: no request is sent
osint-recon domain example.com --authorized --dry-run

# Passive only: never touches example.com's servers
osint-recon domain example.com --passive-only

# Full scan of a domain you are authorised to assess
osint-recon domain example.com --authorized

# Only some sources, JSON only, personal data masked
osint-recon domain example.com -s crtsh,otx,hibp -f json --redact-people

# Your own exposure (needs owned_emails + an HIBP key)
osint-recon footprint
```

| Option | Description |
|---|---|
| `--passive-only` | Run only third-party sources. |
| `--authorized` | Declare you are authorised to actively probe the domain. |
| `-s, --sources` | Comma-separated subset (`crtsh,hackertarget,otx,hunter,hibp,website,documents,dns`). |
| `-f, --format` | `md`, `json` or `both` (default). |
| `--redact-people` | Mask emails and names in the report. |
| `--dry-run` | Show what would run; send no requests. |
| `-o, --output-dir` | Where reports and `osint-recon.log` go (default `reports/`). |
| `-c, --config` | YAML config file. |
| `-v, --verbose` | Debug output. |

Sources run concurrently: stage 1 (passive sources and the crawler) in parallel,
then stage 2 (DNS resolution and documents), which uses what stage 1 found.
**Ctrl+C** writes a report marked *PARTIAL* with whatever had finished.

## API keys

Keys are read from **environment variables** (they take precedence over the
config file, and keep keys out of files you might commit):

```bash
export OSINT_RECON_HUNTER_KEY=...   # https://hunter.io/api-keys (free plan available)
export OSINT_RECON_HIBP_KEY=...     # https://haveibeenpwned.com/API/Key (paid)
export OSINT_RECON_OTX_KEY=...      # optional; OTX works without it at lower limits
```

Without a key, that source is skipped (or degraded, for HIBP and OTX) and the
report says so. Respect each provider's terms of use.

## Configuration

Copy the defaults and change what you need. Your file is merged over the
bundled [`default_config.yaml`](src/osint_recon/data/default_config.yaml):

```yaml
# ~/.config/osint-recon/config.yaml
scope:                 # domains you are authorised to probe actively (subdomains included)
  - mycompany.com
owned_emails:          # YOUR addresses, for `osint-recon footprint`
  - me@mycompany.com
output_dir: ~/osint-reports

sources:
  hackertarget: {enabled: false}       # switch a source off
  hibp: {min_interval: 2.0}            # if your HIBP plan allows more requests/min

crawl:
  max_pages: 50
  max_depth: 2
  max_documents: 30
```

Everything is validated, with messages that say exactly which key is wrong.
Technology fingerprints live in
[`tech_rules.yaml`](src/osint_recon/data/tech_rules.yaml): add a technology by
adding a rule (headers, cookies, generator meta, script URLs, HTML patterns).

## Reports

`reports/<domain>-<timestamp>.md` and `.json`:

- **Summary** counts and a **Sources** table: status, findings, duration and notes
  for every source (why it was skipped, why it failed, quota hit, wildcard DNS...);
- **Subdomains** (with IPs and which sources saw them), **Emails**, **People**,
  **Technologies** (version and evidence), **Documents** (author, last modified
  by, software, dates), **Breaches** grouped by kind.

Every finding records **which sources** reported it, so each claim can be
verified. The JSON has a `schema` field (`osint-recon/report@1`) for tooling.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Report written (individual sources may have failed: see the report) |
| 1 | Unexpected error (details with `-v`) |
| 2 | Invalid domain, option or configuration |
| 4 | Active collection refused: domain not in scope (use `--passive-only` or `--authorized`) |
| 5 | Every source failed (the report with the reasons is still written) |
| 130 | Interrupted with Ctrl+C (a PARTIAL report is written) |

## Development

```bash
pytest                                   # 175 tests, no network access needed
pytest --cov=osint_recon --cov-branch    # 97% line + branch coverage
mypy                                     # strict static typing
ruff check src tests                     # lint
python -m build && twine check dist/*    # build and validate (never uploaded)
```

**No test touches the network.** [respx](https://lundberg.github.io/respx/)
intercepts every `httpx` request (an unmocked request fails the test), the DNS
resolver and the clock are injected, and test documents (PDF, DOCX) are built in
memory. Fixtures reproduce real API responses, noise included: wildcards and
foreign domains in certificates, errors returned with HTTP 200, CNAME records...

## Architecture

```text
src/osint_recon/
├── cli.py            Typer commands, ethical gate, error -> exit code
├── config.py         YAML + environment keys -> validated frozen dataclasses
├── scope.py          domain normalisation (IDNA), ownership checks, active gate
├── runner.py         plan, staged concurrent execution, consolidation, partial state
├── http.py           shared httpx client, retries, Retry-After, capped downloads
├── ratelimit.py      per-source async limiter (min interval + concurrency)
├── models.py         findings dataclasses and de-duplicating merge
├── metadata.py       PDF / OOXML metadata extraction (pure functions)
├── log.py            console + file logging with secret masking
├── errors.py         exception hierarchy with exit codes
├── sources/          one class per source, common `Source` interface
│   ├── crtsh · hackertarget · otx · dns · hunter · hibp
│   ├── website (polite crawler) · techdetect (YAML rules) · documents
├── report/           markdown · json_report · redact · writer (atomic)
└── data/             default_config.yaml · tech_rules.yaml
```

Adding a source means writing one class with `name`, `active`, `stage`,
`key_name` and an `async collect(ctx)` method, and registering it in the runner.

## What this project demonstrates

- **Async Python done properly:** `asyncio` + `httpx`, staged `gather`, a custom
  rate limiter combining a semaphore and minimum spacing, 429/`Retry-After`
  handling that slows a whole source down, cancellation-safe resource release.
- **Resilience:** one failing source never stops the run; network failures and
  server errors are told apart; Ctrl+C yields a partial report; atomic writes.
- **Security and privacy by design:** an ethical gate in code, data
  minimisation, redaction, secret masking in logs, untrusted documents parsed
  safely (magic-byte sniffing, zip-bomb limits, no XXE), `yaml.safe_load`.
- **Testability:** dependency injection (clock, sleep, resolver), HTTP mocked
  with respx, 175 tests, 97% line and branch coverage, `mypy --strict`.
- **Clean, extensible design:** a common `Source` interface, typed frozen
  models with source attribution, YAML-driven technology rules.
- **Modern packaging:** `pyproject.toml` (hatchling), `src/` layout, console
  entry point, PyPI-ready metadata.

## License

[MIT](LICENSE) © 2026 SpromBash
