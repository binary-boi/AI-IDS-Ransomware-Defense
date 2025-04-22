import pickle
import os
import joblib
import numpy as np
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
from rules_engine import load_rules, apply_rules
from datetime import datetime

# === CONFIGURATION ===
MODEL_PATH = "../ml_model/rf_model.pkl"
SCALER_PATH = "../ml_model/scaler.pkl"
RULES_PATH = "../intrusion_detection/rules/detection_rules.json"
INTERFACE = "wlan0"  # Update as per your machine

# === LOAD MODEL & SCALER ===
print(f"Loading model from: {MODEL_PATH}")
model = joblib.load(MODEL_PATH)

scaler = joblib.load(SCALER_PATH)

print("Model and scaler loaded successfully!")
print(f"[DEBUG] Loaded scaler type: {type(scaler)}")

# === LABEL MAPPING === (Edit this based on your dataset's label meanings)
label_map = {
    0: "normal",
    1: "neptune",
    2: "smurf",
    3: "guess_passwd",
    4: "pod",
    5: "teardrop",
    6: "portsweep",
    7: "ipsweep",
    8: "land",
    9: "ftp_write",
    10: "back",
    11: "imap",
    12: "satan",
    13: "phf",
    14: "nmap",
    15: "warezclient",
    16: "warezmaster",
    17: "rootkit",
    18: "buffer_overflow",
    19: "loadmodule",
    20: "perl",
    21: "spy"
}

# === LOAD RULES ===
rules = load_rules(RULES_PATH)

# === FEATURE EXTRACTION ===
def extract_features(packet):
    if not packet.haslayer(IP):
        return None, None

    pkt_info = {
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "protocol": packet[IP].proto,
        "length": len(packet)
    }

    if packet.haslayer(TCP):
        pkt_info.update({
            "src_port": packet[TCP].sport,
            "dst_port": packet[TCP].dport,
            "flags": str(packet[TCP].flags)
        })
    elif packet.haslayer(UDP):
        pkt_info.update({
            "src_port": packet[UDP].sport,
            "dst_port": packet[UDP].dport
        })

    # Use consistent features for ML model
    feature_vector = {
        "src_port": pkt_info.get("src_port", 0),
        "dst_port": pkt_info.get("dst_port", 0),
        "protocol": pkt_info["protocol"],
        "length": pkt_info["length"]
    }

    return pkt_info, pd.DataFrame([feature_vector])

# === PACKET HANDLER ===
def handle_packet(packet):
    pkt_info, features_df = extract_features(packet)
    if pkt_info is None or features_df is None:
        return

    # Apply Rules
    rule_matches = apply_rules(pkt_info, rules)
    for match in rule_matches:
        print(f"[RULE ALERT] Rule ID {match['rule_id']}: {match['description']}")

    # ML Prediction
    try:
        scaled_features = scaler.transform(features_df)
        prediction = model.predict(scaled_features)[0]
        label = label_map.get(prediction, f"Unknown ({prediction})")

        if prediction != 0:
            label = prediction
            print(f"[ML ALERT] Suspicious packet detected! Label: {label}")
            with open("intrusion_log.txt", "a") as log_file:
                log_file.write(f"{datetime.now()} - ML ALERT: {label} - {pkt_info['src_ip']} -> {pkt_info['dst_ip']}\n")

        else:
            print("[OK] Normal packet.")
    except Exception as e:
        print(f"[ERROR] Prediction failed: {e}")

# === START SNIFFING ===
print(f"Starting packet capture on interface: {INTERFACE}")
sniff(iface=INTERFACE, prn=handle_packet, store=0)

