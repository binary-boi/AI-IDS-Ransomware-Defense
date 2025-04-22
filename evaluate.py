from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from joblib import load
import pandas as pd

# Load model and scaler
clf = load('../ml_model/rf_model.joblib')
scaler = load('../ml_model/scaler.joblib')

# Load data
df = pd.read_csv('../data/nsl-kdd/KDDTest+.txt', header=None)
X = df.iloc[:, :-1]
y = df.iloc[:, -1]
y = y.apply(lambda x: 0 if x == 'normal' else 1)

# Scale and predict
X_scaled = scaler.transform(X)
y_pred = clf.predict(X_scaled)

# Results
print(classification_report(y, y_pred))

