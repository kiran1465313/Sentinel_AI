# VPN Sentinel AI

VPN Sentinel AI is a lightweight, explainable security demo for IPsec traffic analysis. It ingests a candidate IPsec profile or PCAP metadata, extracts visible IKE/ESP indicators, scores the configuration using transparent risk rules, and estimates likely encrypted-flow behavior using a small random-forest classifier.

## What this prototype demonstrates

- IKEv1 / IKEv2 detection
- ESP / AH identification
- NAT-T detection via UDP 4500 evidence
- Tunnel vs transport estimation
- SA / SPI tracking
- Crypto posture evaluation
- Explainable risk scoring (0-100)
- Traffic behavior inference: ICMP-like, browsing-like, VoIP-like, video-streaming-like, bulk-transfer-like
- Side-by-side comparison of legacy vs hardened VPN profiles

## Important judge statement

"ESP encrypts payload content, so our classifier does not claim payload decryption. It estimates traffic behavior from flow-level metadata and presents a confidence score. The tool separates an observed fact — such as IKEv2 or AES-GCM — from a probabilistic inference — such as video-like traffic."

## Demo profiles included

- Legacy-risk profile
- Hardened profile

These are intentionally synthetic but realistic enough to show the workflow and the risk logic.

## Run locally

1. Create a virtual environment and install dependencies:
   python -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
2. Launch the dashboard:
   streamlit run app.py
3. Open the local URL shown in the terminal.

## Files

- app.py — Streamlit dashboard
- src/vpn_sentinel.py — scoring engine and ML logic
- data/legacy_profile.json — sample legacy configuration
- data/hardened_profile.json — sample hardened configuration

## Demo story

"Organizations use VPNs believing that encryption alone guarantees security. But a VPN can still be weakened by unsafe cryptography, poor PFS settings, outdated IKE negotiation, and metadata leakage. Manual PCAP inspection needs expert knowledge and takes time."

"VPN Sentinel AI ingests a PCAP from an authorized environment. It identifies IPsec traffic, extracts visible IKE and ESP metadata, evaluates the cryptographic posture, and uses flow metadata to infer the likely traffic class without decrypting user content."

Then show the legacy profile: high-risk score and weak crypto findings; then show the hardened profile: low-risk score and stronger posture; then explain the traffic intelligence output.

## Limitations

This is an explainable prototype designed for a challenge demo. It does not replace full packet forensics or a complete enterprise VPN analyzer.
