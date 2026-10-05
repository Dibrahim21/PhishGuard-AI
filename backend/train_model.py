import pandas as pd
import joblib

from urllib.parse import urlparse

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)

from feature_extractor import extract_url_features


DATASET_PATH = "phishing_url_dataset.csv"
MODEL_PATH = "phishing_model.pkl"


# =================================================
# FEATURE COLUMNS
# Must match feature_extractor.py
# =================================================

FEATURE_COLUMNS = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "dot_count",
    "hyphen_count",
    "digit_count",
    "total_digit_count",
    "total_letter_count",
    "special_character_count",
    "special_url_character_count",
    "subdomain_count",
    "has_https",
    "has_http",
    "has_ip",
    "has_at_symbol",
    "has_double_slash",
    "has_port",
    "is_shortened",
    "keyword_count",
    "query_parameter_count",
    "slash_count",
    "question_count",
    "equal_count",
    "ampersand_count",
    "percent_count",
    "underscore_count",
    "suspicious_tld",
    "common_tld",
    "short_hostname",
    "long_hostname",
    "many_subdomains",
    "many_hyphens",
    "digit_ratio",
    "hostname_digit_ratio",
    "hyphen_ratio",
    "special_character_ratio",
    "hostname_entropy",
    "url_entropy",
    "path_entropy",
]


print("\n==========================================")
print("       PHISHGUARD AI - MODEL TRAINING")
print("==========================================\n")


# =================================================
# 1. LOAD DATASET
# =================================================

print("[1/6] Loading dataset...")

df = pd.read_csv(DATASET_PATH)

df = df.dropna(subset=["URL", "Label"])

before = len(df)

# Remove duplicate URLs
df = df.drop_duplicates(subset=["URL"])

after = len(df)

print(f"Original URLs       : {before}")
print(f"After deduplication : {after}")


# =================================================
# 2. PREPARE DOMAIN GROUPS
# =================================================

print("\n[2/6] Preparing domain groups...")


def get_hostname(url):
    try:
        parsed = urlparse(str(url))
        hostname = parsed.hostname

        if hostname:
            return hostname.lower()

        return ""

    except Exception:
        return ""


df["hostname"] = df["URL"].apply(get_hostname)

# Remove URLs where hostname could not be extracted
df = df[df["hostname"] != ""]

print(f"Usable URLs       : {len(df)}")
print(f"Unique hostnames  : {df['hostname'].nunique()}")


# =================================================
# 3. FEATURE EXTRACTION
# =================================================

print("\n[3/6] Extracting URL features...")
print("This can take a few minutes.\n")


feature_data = []
valid_indices = []

for index, url in enumerate(df["URL"]):

    try:

        features = extract_url_features(str(url))

        # Make sure all required features exist
        missing_features = [
            column
            for column in FEATURE_COLUMNS
            if column not in features
        ]

        if missing_features:
            raise ValueError(
                f"Missing features: {missing_features}"
            )

        feature_data.append(features)

        valid_indices.append(index)

    except Exception as error:

        print(
            f"Skipping URL at index {index}: {error}"
        )

    if (index + 1) % 10000 == 0:
        print(
            f"Processed {index + 1} URLs..."
        )


features_df = pd.DataFrame(feature_data)

df = df.iloc[valid_indices].reset_index(drop=True)

features_df = features_df.reset_index(drop=True)


# =================================================
# CREATE X AND Y
# =================================================

X = features_df[FEATURE_COLUMNS]

y = df["Label"].astype(int)

groups = df["hostname"]


print("\nFeature matrix:")
print(X.shape)

print("\nNumber of features:")
print(len(FEATURE_COLUMNS))

print("\nClass distribution:")
print(y.value_counts())


# =================================================
# 4. DOMAIN-AWARE TRAIN / TEST SPLIT
# =================================================

print("\n[4/6] Creating domain-aware train/test split...")

unique_hosts = groups.drop_duplicates()


train_hosts, test_hosts = train_test_split(
    unique_hosts,
    test_size=0.20,
    random_state=42,
)


train_mask = groups.isin(set(train_hosts))

test_mask = groups.isin(set(test_hosts))


X_train = X[train_mask]

X_test = X[test_mask]

y_train = y[train_mask]

y_test = y[test_mask]


print(f"Training URLs  : {len(X_train)}")
print(f"Testing URLs   : {len(X_test)}")

print(f"Training hosts : {len(train_hosts)}")
print(f"Testing hosts  : {len(test_hosts)}")


# =================================================
# CHECK LABEL DISTRIBUTION
# =================================================

print("\nTraining label distribution:")
print(y_train.value_counts())

print("\nTesting label distribution:")
print(y_test.value_counts())


# =================================================
# 5. TRAIN RANDOM FOREST
# =================================================

print("\n[5/6] Training improved Random Forest...")
print("Please wait...\n")


model = RandomForestClassifier(
    n_estimators=300,
    max_features="sqrt",
    min_samples_leaf=2,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1,
)


model.fit(
    X_train,
    y_train,
)


# =================================================
# 6. EVALUATION
# =================================================

print("\n[6/6] Evaluating model...\n")


y_pred = model.predict(X_test)


# =================================================
# METRICS
# =================================================

accuracy = accuracy_score(
    y_test,
    y_pred,
)


phishing_precision = precision_score(
    y_test,
    y_pred,
    pos_label=0,
    zero_division=0,
)


phishing_recall = recall_score(
    y_test,
    y_pred,
    pos_label=0,
    zero_division=0,
)


phishing_f1 = f1_score(
    y_test,
    y_pred,
    pos_label=0,
    zero_division=0,
)


# =================================================
# PERFORMANCE
# =================================================

print("==========================================")
print("          MODEL PERFORMANCE")
print("==========================================")

print(
    f"Accuracy           : {accuracy * 100:.2f}%"
)

print(
    f"Phishing Precision : {phishing_precision * 100:.2f}%"
)

print(
    f"Phishing Recall    : {phishing_recall * 100:.2f}%"
)

print(
    f"Phishing F1        : {phishing_f1 * 100:.2f}%"
)


# =================================================
# CLASSIFICATION REPORT
# =================================================

print("\n==========================================")
print("        CLASSIFICATION REPORT")
print("==========================================\n")


print(
    classification_report(
        y_test,
        y_pred,
        labels=[0, 1],
        target_names=[
            "Phishing",
            "Legitimate",
        ],
        zero_division=0,
    )
)


# =================================================
# CONFUSION MATRIX
# =================================================

print("==========================================")
print("           CONFUSION MATRIX")
print("==========================================\n")


cm = confusion_matrix(
    y_test,
    y_pred,
    labels=[0, 1],
)


print(cm)

print("\nMatrix format:")
print("[[Phishing Correct, Phishing Wrong]]")
print("[[Legitimate Wrong, Legitimate Correct]]")


# =================================================
# FEATURE IMPORTANCE
# =================================================

print("\n==========================================")
print("          FEATURE IMPORTANCE")
print("==========================================\n")


importance = sorted(
    zip(
        FEATURE_COLUMNS,
        model.feature_importances_,
    ),
    key=lambda x: x[1],
    reverse=True,
)


for feature, value in importance:

    print(
        f"{feature:<30}"
        f"{value * 100:.2f}%"
    )


# =================================================
# SAVE MODEL
# =================================================

joblib.dump(
    {
        "model": model,
        "features": FEATURE_COLUMNS,
    },
    MODEL_PATH,
)


# =================================================
# COMPLETED
# =================================================

print("\n==========================================")
print("       MODEL SAVED SUCCESSFULLY")
print("==========================================")

print(f"File: {MODEL_PATH}")

print("\nTraining completed successfully.")