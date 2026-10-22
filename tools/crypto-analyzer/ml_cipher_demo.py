from sklearn.ensemble import IsolationForest

# Example IoT network activity:
# [packets per minute, failed connections, data sent in MB]

normal_traffic = [
    [100, 1, 5],
    [110, 2, 6],
    [95, 1, 5],
    [105, 2, 6],
    [115, 1, 7],
    [98, 2, 5],
    [108, 1, 6],
    [102, 1, 5],
    [112, 2, 6],
    [97, 1, 5],
]

# Train a machine-learning model on normal traffic
model = IsolationForest(contamination=0.2, random_state=42)
model.fit(normal_traffic)

# Test activity the model has not seen
test_traffic = [
    [103, 1, 5],    # Normal-looking activity
    [1000, 80, 500],  # Unusual activity
    [107, 2, 6],    # Normal-looking activity
]

print("AI-Based IoT Network Anomaly Detection")
print("-" * 40)
print("Model trained on example normal network traffic.\n")

predictions = model.predict(test_traffic)

for i, (traffic, prediction) in enumerate(
    zip(test_traffic, predictions), start=1
):
    result = "Unusual activity flagged" if prediction == -1 else "Normal-looking activity"

    print(f"Test {i}: {traffic}")
    print(f"Result: {result}\n")

print("Note: This is a demonstration using fictional data.")
print("PQC protects communication; this model monitors traffic patterns.")
print("A flagged result does not prove an attack occurred.")
