import pandas as pd

from sklearn.ensemble import IsolationForest

from work import get_sysmon_logs
from feature_extraction import extract_features

pd.set_option('display.max_columns', None)
pd.set_option('display.width', 1000)
pd.set_option('display.max_colwidth', None)


# ==========================================
# 1. COLLECT ALL SYSMON EVENTS
# ==========================================

events = get_sysmon_logs(100)

events = [
    event
    for event in events
    if int(event.get("event_id", 0)) == 1
]



# ==========================================
# 2. EXTRACT FEATURES
# ==========================================

feature_rows = []

for event in events:

    features = extract_features(event)

    feature_rows.append(features)


df = pd.DataFrame(feature_rows)


# ==========================================
# 3. CONVERT TIME
# ==========================================

df["utc_time"] = pd.to_datetime(
    df["utc_time"],
    utc=True
)


# ==========================================
# 4. SORT CHRONOLOGICALLY
# ==========================================

df = df.sort_values("utc_time")


# ==========================================
# 5. TIME-BASED 80/20 SPLIT
# ==========================================

split_index = int(len(df) * 0.80)

train_df = df.iloc[:split_index]

test_df = df.iloc[split_index:].copy()


print("\nTOTAL DATA:")
print(len(df))

print("\nTRAINING DATA:")
print(len(train_df))

print("\nTESTING DATA:")
print(len(test_df))

print("\nTRAINING PERIOD:")
print(train_df["utc_time"].min())
print("TO")
print(train_df["utc_time"].max())

print("\nTESTING PERIOD:")
print(test_df["utc_time"].min())
print("TO")
print(test_df["utc_time"].max())


# ==========================================
# 6. SELECT ML FEATURES
# ==========================================

features_for_ml = [
    "command_length",
    "argument_count",
    "has_powershell",
    "has_script_interpreter"
]


X_train = train_df[features_for_ml]

X_test = test_df[features_for_ml]


# ==========================================
# 7. CREATE ISOLATION FOREST
# ==========================================

model = IsolationForest(
    n_estimators=100,
    contamination="auto",
    random_state=42
)


# ==========================================
# 8. TRAIN
# ==========================================

model.fit(X_train)


print("\nMODEL TRAINING COMPLETE")


# ==========================================
# 9. PREDICT NEWER EVENTS
# ==========================================

predictions = model.predict(X_test)


# ==========================================
# 10. ANOMALY SCORES
# ==========================================

scores = model.decision_function(X_test)


# ==========================================
# 11. ADD RESULTS
# ==========================================

test_df["ml_prediction"] = predictions

test_df["ml_score"] = scores


# ==========================================
# 12. GET ANOMALIES
# ==========================================

anomalies = test_df[
    test_df["ml_prediction"] == -1
]


# ==========================================
# 13. DISPLAY
# ==========================================

print("\nNUMBER OF ANOMALIES:")
print(len(anomalies))


print("\nTOP 20 MOST UNUSUAL EVENTS:")

columns_to_show = [
    "utc_time",
    "EventRecordID",
    "Image",
    "CommandLine",
    "ParentImage",
    "ParentCommandLine",
    "User",
    "ml_score"
]

print(
    anomalies[columns_to_show]
    .sort_values("ml_score")
    .head(20)
    .to_string(index=False)
)

#https://www.edx.org/learn/test-prep/the-university-of-queensland-ielts-academic-test-preparation