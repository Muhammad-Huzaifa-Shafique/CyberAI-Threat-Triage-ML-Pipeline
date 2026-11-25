# CyberAI: Threat Triage Tool

CyberAI is a Python tool that helps you decide quickly whether a **link**, **email**, or **PDF** looks safe. It runs several security checks at once and gives a plain verdict (**Clean**, **Suspicious**, or **Malware**) along with the reasons behind it.

Use it from the command line or in a small web page on your own computer. It can also save your results as a PDF report.

## What this repository shows

This repository holds the rule-based triage tool. It scores a link, an email or a PDF with fixed points, lists the reasons behind the verdict, and saves each result to a local database. Its point values are set by hand, and its accuracy has not been measured.

CyberAI is larger than this tool. The wider project adds a machine-learning scoring pipeline (logistic regression, Isolation Forest, an elastic-net risk score, a drift monitor and a human-review queue) and an offline-first chat assistant that answers from a local cache and shows its evidence. That source is not published here yet. [ARCHITECTURE.md](ARCHITECTURE.md) explains how those parts work, with excerpts from the real code, a list of what is not measured and a list of known issues. Interactive explainers are on the [portfolio page](https://muhammad-huzaifa-shafique.github.io/cyberai.html).

**Try it in the browser.** The [live demo](https://muhammad-huzaifa-shafique.github.io/cyberai.html#try) runs this tool's offline rules (URL warning signs, the look-alike check, the email wording and Reply-To rules, and the verdict thresholds) in JavaScript, so nothing you type is sent anywhere. It does not call VirusTotal, DNS or the other online checks. I compared that port with `CyberAI.py` on 28,600 cases and found no differences. The [test scripts, and the one limit of the test](https://github.com/Muhammad-Huzaifa-Shafique/Muhammad-Huzaifa-Shafique.github.io/tree/main/tests/cyberai-parity), are public.

| What an AI/ML team looks for | Where it shows up in this tool |
|---|---|
| Features built from domain knowledge | Hand-written signals. For a URL: many hyphens, a long chain of subdomains, a very long domain, non-ASCII characters, and words such as "login" or "verify". For an email: a domain that looks like a trusted one (string similarity), SPF, DMARC and DKIM results, a Reply-To that differs from the sender, and phishing-style wording |
| A baseline you can explain | Findings add points (see "How the verdict is decided"), and the reasons behind a verdict are listed with it. A score of 5 or more is Malware, 1 to 4 is Suspicious, and 0 is Clean |
| Code that copes with unreliable outside services | VirusTotal, DNS and RDAP lookups have timeouts (20, 5 and 10 seconds), and a failed lookup comes back as an error note instead of stopping the run. The API key is read from an environment variable, never from the code |
| Work that people can use | A command line, a small web page, a local SQLite history of past results and a PDF report |

**Not measured yet.** There is no accuracy figure for the triage score or for the machine-learning pipeline. The weights in this tool were not learned from data, and informational notes such as "SPF found" also add a point to an email's score (see "Good to know"). ARCHITECTURE.md explains why the training data in the working copy could not support a meaningful test.

## What it can check

| You give it | What CyberAI does |
|---|---|
| **A URL** | Looks up the link's VirusTotal report, reads its DNS records, finds who registered the domain (RDAP), checks the mail-server IPs against spam blocklists, and flags warning signs such as many hyphens, very long domains, unusual characters, or words like "login" and "verify". |
| **An email** (an address, pasted raw text, or an `.eml` file) | Checks the sender's domain for look-alike or spoofed names, looks for SPF and DMARC records, verifies DKIM signatures (for `.eml` files), spots phishing-style wording and a Reply-To that differs from the sender, and checks IPs in the headers against spam blocklists. |
| **A PDF** | Extracts the links found inside the file. |

Every result is also saved to a local database (`threat_history.db`) so you can review it later.

## How the verdict is decided

Each finding adds points to a score:

- VirusTotal: 2 points per "malicious" detection, 1 point per "suspicious"
- Each spam-blocklist listing: 2 points
- URL warning signs: up to 2 points
- Each email alert: 1 point

A score of **5 or more** is **Malware**, **1 to 4** is **Suspicious**, and **0** is **Clean**.

## Getting started

You need Python 3.8 or newer.

```bash
git clone https://github.com/Muhammad-Huzaifa-Shafique/CyberAI.git
cd CyberAI
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Add your VirusTotal key (optional)

The VirusTotal check needs a free API key from [virustotal.com](https://www.virustotal.com). Give it to the tool through an environment variable, and never paste keys into the code:

```bash
export VIRUSTOTAL_API_KEY="your-key-here"          # macOS / Linux
$env:VIRUSTOTAL_API_KEY = "your-key-here"          # Windows PowerShell
```

Without a key, everything else still works and the VirusTotal part is skipped.

## Using it

```bash
python CyberAI.py                  # interactive command-line mode
python CyberAI.py --mode serve     # web page at http://127.0.0.1:8080
python CyberAI.py --mode history   # show the 10 most recent results
python CyberAI.py --save-pdf       # create a PDF report from saved history, then exit
```

In command-line mode, choose `url`, `email`, or `pdf`, then paste a link, an email address, raw email text, or a file path. Type `exit` to quit. In web mode, `--host` and `--port` change the address.

### Reports

- When you leave command-line mode, a report is saved as `Threat Detection Results.pdf` in your Downloads folder.
- In web mode, the latest report can be downloaded at `/download`.

### Optional: your own trusted domains

The look-alike check compares domains against a built-in list (pittstate.edu, paypal.com, google.com, microsoft.com, apple.com). To use your own list, add a `trusted_domains.json` file next to `CyberAI.py`:

```json
["yourcompany.com", "google.com", "paypal.com"]
```

## Project files

| File | Purpose |
|---|---|
| `CyberAI.py` | The whole tool: analysis checks, command line, web page, and PDF reports |
| `requirements.txt` | Python packages to install |
| `ARCHITECTURE.md` | How the machine-learning pipeline and the chat assistant work, with code excerpts, what is not measured and known issues |

## Good to know

- It needs an internet connection (DNS, RDAP, and VirusTotal lookups). Free VirusTotal keys have usage limits.
- VirusTotal checks use the existing report for a URL; new URLs are not submitted for scanning.
- Results are meant for quick triage, not final verdicts. Informational notes (like "SPF found") currently count toward an email's score, so a "Suspicious" label is a cue to look closer.
- PDF mode currently only extracts links; it does not scan them yet.
- This tool supports learning and first-pass checks. It does not replace antivirus or professional security tools.

## Author

Made by [Muhammad Huzaifa Shafique](https://github.com/Muhammad-Huzaifa-Shafique).
