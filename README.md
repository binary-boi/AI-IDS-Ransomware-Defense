# AI-IDS-Ransomware-Defense


This project is a hybrid AI-powered Intrusion Detection and Ransomware Mitigation System. It leverages machine learning models, packet inspection, and behavioral monitoring to detect and respond to network threats and ransomware activity.

---

## 🧠 Features

### 🔍 Intrusion Detection (IDS)
- Real-time packet sniffing using **Scapy**
- ML-based classification using **Random Forest**
- Custom rule-based engine to match suspicious patterns
- Supports NSL-KDD and CIC-IDS-2017 datasets

### 🛡️ Ransomware Defense
- Honeypot system to detect ransomware access attempts
- Cloud backup automation (AWS/GCP-ready for future deployment)

---

## 📁 Project Structure

AI-IDS-Ransomware-Defense/ 
├── data/                      # Datasets (CIC-IDS-2017, NSL-KDD)

├── ml_model/                  # Machine learning code
│   ├── train.py               # Train Random Forest + Autoencoder
│   └── evaluate.py            # Test model performance

├── intrusion_detection/       # Real-time detection
│   ├── detector.py            # Scapy-based packet sniffer
│   └── rules/                 # Custom detection rules

├── ransomware_defense/        # Anti-ransomware tools
│   ├── honeypot.py            # Decoy file monitor


└── README.md                  # Project documentation


---

## ⚙️ Installation


git clone https://github.com/binary-boi/AI-IDS-Ransomware-Defense.git
cd AI-IDS-Ransomware-Defense
python3.11 -m venv tfenv
source tfenv/bin/activate
pip install -r requirements.txt

Requirements
Python 3.11+
pandas, scikit-learn, tensorflow, scapy, watchdog, boto3
Wireshark/tshark (optional for pcap analysis)

License & Credits
This project is for educational and demonstration purposes. I have created it as part of my Masters Research project at Saint Louis University 2025
Inspired by real-world SOC operations and modern cybersecurity practices.

Author
Akshay Kumar Sankalapuram
Cybersecurity Master's Student | Capture The Flag Competitor | Security+ Certified
