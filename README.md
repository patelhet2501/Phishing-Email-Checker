# Phishing Email Checker

Phishing Email Checker is a Python tool that helps SOC analysts quickly triage suspected phishing emails. It parses raw `.eml` files, extracts key headers and URLs, and runs a set of lightweight checks for common phishing indicators.

## Problem

When users report suspicious emails, analysts often have to:

- Manually open the email or raw headers
- Verify SPF/DKIM/DMARC results by eye
- Inspect embedded URLs for lookalike domains or URL shorteners
- Skim the body for social engineering language

This is repetitive, error‑prone work and slows down first‑pass triage.

## Solution Overview

This project automates that first pass:

- Accepts a raw email file (`.eml`) as input
- Parses headers and body using Python’s standard `email` library
- Extracts and analyses:
  - Authentication headers (SPF, DKIM, DMARC) from `Authentication-Results` and related fields
  - Embedded URLs in the message body
  - Body text for common social engineering patterns
- Produces a simple, structured report highlighting suspicious signals and an overall risk score

The goal is not to be a full ML detector, but a practical helper that surfaces red flags quickly for an analyst.

## Features (Planned / In Development)

- Header parsing:
  - Extract `From`, `Reply-To`, `Return-Path`, `Authentication-Results`, and all raw headers
  - Parse SPF/DKIM/DMARC verdicts where present
- URL analysis:
  - Extract URLs from plain‑text and HTML bodies
  - Flag URL shorteners and unusual TLDs
  - Detect basic lookalike domains (e.g. `paypa1.com`, `micros0ft.support`)
- Content heuristics:
  - Highlight common phishing phrases and urgency cues
  - Simple scoring model to combine header, URL, and content findings

## Tech Stack

- Python 3
- Standard library: `email`, `re`, `argparse`, `urllib.parse`
- Optional future integrations:
  - Domain reputation APIs
  - URL sandboxing services

## Usage (design)

The tool is designed to be run from the command line:

```bash
python src/main.py path/to/suspicious_email.eml
```

Example output (conceptual):

- Header authentication summary (SPF/DKIM/DMARC pass/fail)
- List of extracted URLs with basic risk tags
- Notable phrases / patterns in the body
- Overall risk score (e.g. 0–100) to prioritise investigation

## Status

This is an in‑progress portfolio project focused on:

- Clean parsing of `.eml` files
- Clear, explainable heuristics for phishing detection
- A workflow that mirrors how SOC analysts actually triage reported emails
>>>>>>> 9e16356 (docs: add README and initial requirements)
