import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report
import joblib
import os
import pickle

# Load dataset
data_path = '../data/nsl-kdd/KDDTrain+.txt'
column_names = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label"
]

df = pd.read_csv(data_path, names=column_names)

# Drop rows with missing values (if any)
df.dropna(inplace=True)

# Simulate fields to match live features
df['src_port'] = np.random.randint(1024, 65535, size=len(df))
df['dst_port'] = np.random.randint(1024, 65535, size=len(df))
df['protocol'] = df['protocol_type'].map({'tcp': 6, 'udp': 17, 'icmp': 1}).fillna(0).astype(int)
df['length'] = df['srv_count']  # use this field as packet "length"

# Use only the real-time fields
X = df[['src_port', 'dst_port', 'protocol', 'length']]
y = df['label']

# Encode labels
label_encoder = LabelEncoder()
y = label_encoder.fit_transform(y)

# Feature scaling
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train model
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_scaled, y)

# Save model and scaler
model_dir = '../ml_model'
os.makedirs(model_dir, exist_ok=True)
joblib.dump(clf, os.path.join(model_dir, 'rf_model.pkl'))
joblib.dump(scaler, os.path.join(model_dir, 'scaler.pkl'))

# Evaluate on training set (initial check)
y_pred = clf.predict(X_scaled)
print(classification_report(y, y_pred))
