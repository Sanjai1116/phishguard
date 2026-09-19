import pandas as pd
import joblib
from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report


# --------------------------------------------------
# 1. Project paths
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

DATASET_PATH = BASE_DIR / "datasets" / "url_dataset.csv"
MODEL_DIR = BASE_DIR / "model"
MODEL_PATH = MODEL_DIR / "url_model.joblib"


# --------------------------------------------------
# 2. Load dataset
# --------------------------------------------------

print("Loading URL dataset...")

df = pd.read_csv(DATASET_PATH)

required_columns = {"url", "label"}

if not required_columns.issubset(df.columns):
    raise ValueError(
        "Dataset must contain 'url' and 'label' columns."
    )

df = df.dropna(subset=["url", "label"])

df["url"] = df["url"].astype(str)
df["label"] = df["label"].astype(str).str.lower().str.strip()


# --------------------------------------------------
# 3. Check dataset
# --------------------------------------------------

print(f"Total samples: {len(df)}")
print("\nClass distribution:")
print(df["label"].value_counts())


# --------------------------------------------------
# 4. Split dataset
# --------------------------------------------------

X = df["url"]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


# --------------------------------------------------
# 5. Create ML pipeline
# --------------------------------------------------

model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            analyzer="char",
            ngram_range=(3, 5),
            min_df=1,
            max_features=10000
        )
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000,
            random_state=42
        )
    )
])


# --------------------------------------------------
# 6. Train model
# --------------------------------------------------

print("\nTraining URL ML model...")

model.fit(X_train, y_train)


# --------------------------------------------------
# 7. Test model
# --------------------------------------------------

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("\nModel training completed.")
print(f"Accuracy: {accuracy * 100:.2f}%")

print("\nClassification Report:")
print(classification_report(y_test, predictions))


# --------------------------------------------------
# 8. Save trained model
# --------------------------------------------------

MODEL_DIR.mkdir(parents=True, exist_ok=True)

joblib.dump(model, MODEL_PATH)

print("\nModel saved successfully!")
print(f"Location: {MODEL_PATH}")