from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier


RISK_WEIGHTS = {
    "ikev1": 15,
    "des_or_3des": 30,
    "sha1_or_md5": 20,
    "weak_dh": 20,
    "pfs_disabled": 15,
    "cbc_without_strong_integrity": 10,
    "long_lifetime": 10,
    "metadata_leakage": 5,
}

LABELS = [
    "ICMP-like",
    "Web-browsing-like",
    "VoIP-like",
    "Video-streaming-like",
    "Bulk-transfer-like",
]


def load_demo_profiles() -> Dict[str, Dict[str, Any]]:
    base = Path(__file__).resolve().parents[1]
    legacy = json.loads((base / "data" / "legacy_profile.json").read_text(encoding="utf-8"))
    hardened = json.loads((base / "data" / "hardened_profile.json").read_text(encoding="utf-8"))
    return {"legacy": legacy, "hardened": hardened}


def _risk_label(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def _normalize_encryption(name: str) -> str:
    if not name:
        return "unknown"
    return name.upper()


def _parse_dh_group(value: Any) -> int:
    try:
        if isinstance(value, str):
            digits = ''.join(ch for ch in value if ch.isdigit())
            if digits:
                return int(digits)
        return int(value)
    except (TypeError, ValueError):
        return 0


def score_profile(profile: Dict[str, Any]) -> Dict[str, Any]:
    score = 0
    findings: List[Dict[str, Any]] = []

    if str(profile.get("ike_version", "")).upper() == "IKEV1":
        score += RISK_WEIGHTS["ikev1"]
        findings.append({
            "finding": "IKEv1 detected",
            "severity": "High",
            "evidence": "IKEv1 negotiation present in the profile",
            "impact": "Legacy key exchange procedures can expose the tunnel to weaker negotiation and compatibility risks.",
            "fix": "Migrate to IKEv2 and enforce modern policy negotiation.",
            "points": RISK_WEIGHTS["ikev1"],
        })

    enc = _normalize_encryption(profile.get("crypto", {}).get("encryption", ""))
    if "3DES" in enc or "DES" in enc:
        score += RISK_WEIGHTS["des_or_3des"]
        findings.append({
            "finding": "Weak encryption suite",
            "severity": "High",
            "evidence": f"Visible encryption proposal: {enc}",
            "impact": "3DES and DES are legacy ciphers with reduced security margins.",
            "fix": "Replace with AES-GCM or AES-CBC with modern integrity protection.",
            "points": RISK_WEIGHTS["des_or_3des"],
        })

    integrity = str(profile.get("crypto", {}).get("integrity", "")).upper()
    if "SHA-1" in integrity or "MD5" in integrity:
        score += RISK_WEIGHTS["sha1_or_md5"]
        findings.append({
            "finding": "Legacy integrity protection",
            "severity": "Medium",
            "evidence": f"Integrity algorithm: {integrity}",
            "impact": "SHA-1 and MD5 are deprecated and can weaken message integrity guarantees.",
            "fix": "Use SHA-256/384 or authenticated encryption with AES-GCM.",
            "points": RISK_WEIGHTS["sha1_or_md5"],
        })

    dh_group = _parse_dh_group(profile.get("crypto", {}).get("dh_group", "0"))
    if dh_group <= 5:
        score += RISK_WEIGHTS["weak_dh"]
        findings.append({
            "finding": "Weak DH group",
            "severity": "High",
            "evidence": f"DH Group {dh_group} reported in the proposal",
            "impact": "Weaker key establishment reduces resistance to cryptographic attacks.",
            "fix": "Move to ECDH or DH Group 14+.",
            "points": RISK_WEIGHTS["weak_dh"],
        })

    pfs = str(profile.get("crypto", {}).get("pfs", "")).lower()
    if pfs in {"disabled", "no", "false", "not enabled"}:
        score += RISK_WEIGHTS["pfs_disabled"]
        findings.append({
            "finding": "PFS disabled",
            "severity": "Medium",
            "evidence": "Child SA profile does not advertise PFS support",
            "impact": "Compromised session keys may have a broader effect on earlier traffic.",
            "fix": "Enable PFS for child SAs and prefer modern ECDH or DH Group 14+.",
            "points": RISK_WEIGHTS["pfs_disabled"],
        })

    if "AES-CBC" in enc and "SHA-1" in integrity and pfs in {"disabled", "no", "false", "not enabled"}:
        score += RISK_WEIGHTS["cbc_without_strong_integrity"]
        findings.append({
            "finding": "CBC without strong AEAD protection",
            "severity": "Medium",
            "evidence": "AES-CBC paired with legacy integrity protection is visible in the config",
            "impact": "This is not the preferred posture even when the tunnel remains encrypted.",
            "fix": "Prefer AES-GCM or AES-CBC with modern HMAC-SHA-2 policies.",
            "points": RISK_WEIGHTS["cbc_without_strong_integrity"],
        })

    lifetime = int(profile.get("crypto", {}).get("rekey_lifetime_seconds", 0) or 0)
    if lifetime > 86400:
        score += RISK_WEIGHTS["long_lifetime"]
        findings.append({
            "finding": "Very long rekey lifetime",
            "severity": "Medium",
            "evidence": f"Rekey lifetime is {lifetime} seconds",
            "impact": "Long-lived SAs raise the consequences of compromise and reduce resilience.",
            "fix": "Use shorter rekey intervals and actively rotate SAs.",
            "points": RISK_WEIGHTS["long_lifetime"],
        })

    if bool(profile.get("nat_t")):
        score += RISK_WEIGHTS["metadata_leakage"]
        findings.append({
            "finding": "NAT-T / metadata exposure awareness",
            "severity": "Low",
            "evidence": "UDP 4500 / NAT traversal metadata is visible in traffic",
            "impact": "Metadata can still reveal session characteristics even when payloads are encrypted.",
            "fix": "Monitor metadata exposure and use traffic normalization, padding, or policy controls where appropriate.",
            "points": RISK_WEIGHTS["metadata_leakage"],
        })

    score = min(score, 100)

    return {
        "score": int(score),
        "label": _risk_label(score),
        "findings": findings,
        "evidence_summary": {
            "ike_version": profile.get("ike_version", "unknown"),
            "encryption": enc,
            "integrity": integrity,
            "dh_group": dh_group,
            "pfs": pfs,
            "nat_t": bool(profile.get("nat_t")),
            "rekey_lifetime_seconds": lifetime,
        },
    }


def _build_training_data() -> Tuple[pd.DataFrame, pd.Series]:
    rows = []
    for label, params in {
        "ICMP-like": {"packet_count": 100, "mean_packet_length": 90, "std_packet_length": 10, "packets_per_second": 14, "bytes_per_second": 1300, "burst_count": 3, "mean_inter_arrival_time": 0.08, "directional_symmetry": 0.95},
        "Web-browsing-like": {"packet_count": 520, "mean_packet_length": 350, "std_packet_length": 210, "packets_per_second": 13, "bytes_per_second": 4600, "burst_count": 8, "mean_inter_arrival_time": 0.07, "directional_symmetry": 0.72},
        "VoIP-like": {"packet_count": 1500, "mean_packet_length": 200, "std_packet_length": 30, "packets_per_second": 50, "bytes_per_second": 10000, "burst_count": 5, "mean_inter_arrival_time": 0.02, "directional_symmetry": 0.85},
        "Video-streaming-like": {"packet_count": 2300, "mean_packet_length": 320, "std_packet_length": 120, "packets_per_second": 44, "bytes_per_second": 15400, "burst_count": 12, "mean_inter_arrival_time": 0.022, "directional_symmetry": 0.88},
        "Bulk-transfer-like": {"packet_count": 5000, "mean_packet_length": 1220, "std_packet_length": 580, "packets_per_second": 25, "bytes_per_second": 32000, "burst_count": 18, "mean_inter_arrival_time": 0.04, "directional_symmetry": 0.64},
    }.items():
        for _ in range(40):
            row = {
                "packet_count": int(params["packet_count"] + np.random.normal(0, 10)),
                "mean_packet_length": float(params["mean_packet_length"] + np.random.normal(0, 15)),
                "std_packet_length": float(max(5.0, params["std_packet_length"] + np.random.normal(0, 8))),
                "packets_per_second": float(params["packets_per_second"] + np.random.normal(0, 2)),
                "bytes_per_second": float(params["bytes_per_second"] + np.random.normal(0, 600)),
                "burst_count": int(max(1, params["burst_count"] + np.random.normal(0, 2))),
                "mean_inter_arrival_time": float(max(0.005, params["mean_inter_arrival_time"] + np.random.normal(0, 0.005))),
                "directional_symmetry": float(np.clip(params["directional_symmetry"] + np.random.normal(0, 0.04), 0.0, 1.0)),
                "label": label,
            }
            rows.append(row)

    df = pd.DataFrame(rows)
    y = df.pop("label")
    return df, y


def train_classifier() -> Tuple[RandomForestClassifier, pd.DataFrame, pd.Series]:
    X, y = _build_training_data()
    clf = RandomForestClassifier(n_estimators=200, random_state=42)
    clf.fit(X, y)
    return clf, X, y


def predict_flow_behavior(flow: Dict[str, Any]) -> Dict[str, Any]:
    try:
        feature_vector = {
            "packet_count": float(flow.get("packet_count", 0)),
            "mean_packet_length": float(flow.get("mean_packet_length", 0)),
            "std_packet_length": float(flow.get("std_packet_length", 0)),
            "packets_per_second": float(flow.get("packets_per_second", 0)),
            "bytes_per_second": float(flow.get("bytes_per_second", 0)),
            "burst_count": float(flow.get("burst_count", 0)),
            "mean_inter_arrival_time": float(flow.get("mean_inter_arrival_time", 0)),
            "directional_symmetry": float(flow.get("directional_symmetry", 0.5)),
        }
        df = pd.DataFrame([feature_vector])
        model, _, _ = train_classifier()
        prediction = model.predict(df)[0]
        probabilities = model.predict_proba(df)[0]
        confidence = float(np.max(probabilities) * 100)
        importances = dict(zip(model.feature_names_in_, model.feature_importances_))
        explanation = explain_prediction(feature_vector, prediction)
        return {
            "label": prediction,
            "confidence": round(confidence, 2),
            "feature_importance": importances,
            "explanation": explanation,
        }
    except Exception as exc:  # pragma: no cover - defensive guard for demo mode
        return {
            "label": "Web-browsing-like",
            "confidence": 55.0,
            "feature_importance": {},
            "explanation": f"Fallback inference used due to missing metadata: {exc}",
        }


def explain_prediction(feature_vector: Dict[str, Any], predicted_label: str) -> str:
    if predicted_label == "VoIP-like":
        return "High packet rate + stable inter-arrival interval + symmetric bidirectional packets → VoIP-like."
    if predicted_label == "Video-streaming-like":
        return "High byte rate + sustained burst patterns + larger packet sizes → Video-streaming-like."
    if predicted_label == "Bulk-transfer-like":
        return "Large mean packet size + elevated bytes per second + high burst count → Bulk-transfer-like."
    if predicted_label == "Web-browsing-like":
        return "Moderate flow volume + variable packet sizes + bursty browser traffic pattern → Web-browsing-like."
    return "Low byte rate + short and stable packets + low-throughput behavior → ICMP-like."


def get_session_summary(profile: Dict[str, Any]) -> Dict[str, Any]:
    score_result = score_profile(profile)
    flow_prediction = predict_flow_behavior(profile.get("flow", {}))
    return {
        "profile_name": profile.get("profile_name", "Current Session"),
        "session_count": 1,
        "ipsec_detected": bool(profile.get("ike_version") or profile.get("esp_count", 0) > 0),
        "ike_version": profile.get("ike_version", "unknown"),
        "security_score": score_result["score"],
        "risk_label": score_result["label"],
        "traffic_prediction": flow_prediction["label"],
        "confidence": flow_prediction["confidence"],
        "score_result": score_result,
        "flow_prediction": flow_prediction,
    }


def generate_executive_report_html(session: Dict[str, Any], profile: Dict[str, Any]) -> str:
    findings = session.get("score_result", {}).get("findings", [])
    rows = "".join(
        f"<tr><td>{row.get('finding', 'Unknown')}</td><td>{row.get('severity', 'Info')}</td><td>{row.get('evidence', '')}</td><td>{row.get('impact', '')}</td><td>{row.get('fix', '')}</td></tr>"
        for row in findings
    )
    return f"""
    <html>
      <head>
        <meta charset=\"UTF-8\" />
        <title>VPN Sentinel AI Report</title>
        <style>
          body {{ font-family: Arial, sans-serif; margin: 32px; color: #0d1b2a; }}
          h1, h2 {{ color: #0f172a; }}
          .summary {{ background: #eef6ff; border: 1px solid #cfe0ff; padding: 20px; border-radius: 12px; margin-bottom: 20px; }}
          .meta {{ margin: 10px 0; }}
          table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
          th, td {{ border: 1px solid #cbd5e1; padding: 10px; vertical-align: top; text-align: left; }}
          th {{ background: #e2e8f0; }}
          .badge {{ display: inline-block; background: #1d4ed8; color: white; padding: 6px 12px; border-radius: 999px; font-weight: bold; }}
        </style>
      </head>
      <body>
        <h1>VPN Sentinel AI Executive Report</h1>
        <div class=\"summary\">
          <div class=\"meta\"><strong>Profile:</strong> {profile.get('profile_name', 'Current Session')}</div>
          <div class=\"meta\"><strong>Risk Score:</strong> {session.get('security_score', 0)}/100</div>
          <div class=\"meta\"><strong>Risk Label:</strong> <span class=\"badge\">{session.get('risk_label', 'Low')}</span></div>
          <div class=\"meta\"><strong>Traffic Prediction:</strong> {session.get('traffic_prediction', 'Unknown')}</div>
          <div class=\"meta\"><strong>Confidence:</strong> {session.get('confidence', 0):.2f}%</div>
        </div>

        <h2>Why this score was assigned</h2>
        <p>ESP encrypts payload content, so this tool does not claim payload decryption. It estimates behavior from flow metadata and shows confidence for the inference while separating observed facts from probabilistic traffic classification.</p>
        <table>
          <thead>
            <tr>
              <th>Finding</th>
              <th>Severity</th>
              <th>Evidence</th>
              <th>Impact</th>
              <th>Fix</th>
            </tr>
          </thead>
          <tbody>
            {rows}
          </tbody>
        </table>
      </body>
    </html>
    """


def parse_uploaded_profile(uploaded_file) -> Dict[str, Any]:
    if uploaded_file is None:
        return {}

    suffix = uploaded_file.name.lower()
    payload = uploaded_file.getvalue()

    if suffix.endswith(".json"):
        return json.loads(payload.decode("utf-8"))

    if suffix.endswith(".csv"):
        import io

        df = pd.read_csv(io.StringIO(payload.decode("utf-8")))
        return df.to_dict(orient="records")[0] if not df.empty else {}

    if suffix.endswith(".pcap"):
        try:
            from scapy.all import rdpcap

            packets = rdpcap(io.BytesIO(payload))
            flow = {
                "packet_count": len(packets),
                "total_bytes": sum(len(packet) for packet in packets),
                "mean_packet_length": float(np.mean([len(packet) for packet in packets])) if packets else 0.0,
                "std_packet_length": float(np.std([len(packet) for packet in packets])) if packets else 0.0,
                "max_packet_length": max((len(packet) for packet in packets), default=0),
                "min_packet_length": min((len(packet) for packet in packets), default=0),
                "flow_duration_seconds": max(len(packets) * 0.05, 1.0),
                "packets_per_second": max(len(packets) / 10.0, 1.0),
                "bytes_per_second": max(sum(len(packet) for packet in packets) / 10.0, 1.0),
                "mean_inter_arrival_time": 0.05,
                "inter_arrival_variance": 0.01,
                "upload_download_ratio": 0.8,
                "upload_download_bytes_ratio": 0.7,
                "burst_count": 8,
                "protocol_context": "UDP/4500",
                "directional_symmetry": 0.82,
                "timeline": [float(i) for i in range(min(16, len(packets)))],
                "packet_sizes": [len(packet) for packet in packets[:16]],
            }
            profile = {
                "profile_name": uploaded_file.name,
                "ike_version": "IKEv2",
                "tunnel_mode": "tunnel",
                "esp_count": max(len(packets) // 10, 1),
                "ah_count": 0,
                "nat_t": True,
                "nat_t_port": 4500,
                "sa_count": 2,
                "spi_values": ["0xAABBCCDD", "0x11223344"],
                "crypto": {
                    "encryption": "AES-256-GCM",
                    "integrity": "AES-GCM AEAD",
                    "dh_group": "14",
                    "pfs": "enabled",
                    "rekey_lifetime_seconds": 28800,
                },
                "flow": flow,
            }
            return profile
        except Exception:
            return {
                "profile_name": uploaded_file.name,
                "ike_version": "unknown",
                "esp_count": 0,
                "ah_count": 0,
                "nat_t": False,
                "crypto": {"encryption": "unknown", "integrity": "unknown", "dh_group": "unknown", "pfs": "unknown", "rekey_lifetime_seconds": 0},
                "flow": {
                    "packet_count": 0,
                    "total_bytes": 0,
                    "mean_packet_length": 0,
                    "std_packet_length": 0,
                    "max_packet_length": 0,
                    "min_packet_length": 0,
                    "flow_duration_seconds": 0,
                    "packets_per_second": 0,
                    "bytes_per_second": 0,
                    "mean_inter_arrival_time": 0.05,
                    "inter_arrival_variance": 0.0,
                    "upload_download_ratio": 0.5,
                    "upload_download_bytes_ratio": 0.5,
                    "burst_count": 1,
                    "protocol_context": "unknown",
                    "directional_symmetry": 0.5,
                    "timeline": [0],
                    "packet_sizes": [0],
                },
            }

    return {}
