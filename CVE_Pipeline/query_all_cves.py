"""
Query the model and show ALL matching CVEs
"""

import joblib
from sklearn.metrics.pairwise import cosine_similarity
import os

MODEL_FOLDER = r"D:\Downloads\CAVE-OT Datasets\model"

# Load the OT model
print("Loading model...")
ot_vectorizer = joblib.load(os.path.join(MODEL_FOLDER, 'ot_vectorizer.pkl'))
ot_matrix = joblib.load(os.path.join(MODEL_FOLDER, 'ot_matrix.pkl'))
ot_cve_database = joblib.load(os.path.join(MODEL_FOLDER, 'ot_cve_database.pkl'))

# Your query
query = "siemens simatic s7-1200 v4.1 profinet"

print(f"\nQuery: {query}")
print(f"\nModel finds ALL matching CVEs:\n")

# Convert query to vector
query_vector = ot_vectorizer.transform([query.lower()])

# Find similar CVEs
scores = cosine_similarity(query_vector, ot_matrix).flatten()

# Get top 20 results (or change to 50, 100, etc.)
TOP_K = 20
top_idx = scores.argsort()[-TOP_K:][::-1]

# Display ALL results
for idx in top_idx:
    cve = ot_cve_database.iloc[idx]
    print(f"{cve['cve_id']} cvss={cve['cvss']:.1f} epss={cve['epss']:.3f} kev={cve['kev']}")

print(f"\n✓ Showed top {TOP_K} CVEs")
print(f"  (Change TOP_K variable to show more)")
