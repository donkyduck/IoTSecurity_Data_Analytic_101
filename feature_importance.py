from warnings import simplefilter

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import (
    StratifiedKFold,
    cross_val_score,
    cross_val_predict,
    train_test_split,
)
from sklearn.naive_bayes import GaussianNB
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler, label_binarize
from sklearn.tree import DecisionTreeClassifier

simplefilter(action="ignore", category=FutureWarning)

RANDOM_STATE = 0
N_SPLITS = 5

# ============================================================
# Load dataset
# ============================================================

df = pd.read_csv("label_feature_IOT.csv")

# First column = label
label_col = df.columns[0]
feature_names = list(df.columns[1:])

# Last 5 columns are assumed to be hex fields
hex_columns = df.columns[-5:]

for col in hex_columns:
    df[col] = df[col].apply(lambda x: int(str(x), 16) if pd.notna(x) else 0)

X = df.iloc[:, 1:].copy()
y = df.iloc[:, 0].copy()

# Encode labels
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)
class_names = label_encoder.classes_

# Hold-out split
x_train, x_test, y_train, y_test = train_test_split(
    X,
    y_encoded,
    test_size=0.25,
    random_state=RANDOM_STATE,
    stratify=y_encoded,
)

# Cross-validation strategy
cv = StratifiedKFold(n_splits=N_SPLITS, shuffle=True, random_state=RANDOM_STATE)

print("Begin:__________________________________")


# ============================================================
# Utility functions
# ============================================================

def print_stats_metrics(y_true, y_pred, class_names):
    print(f"Accuracy: {accuracy_score(y_true, y_pred):.3f}")
    print("Confusion matrix")
    print(confusion_matrix(y_true=y_true, y_pred=y_pred))
    print(pd.crosstab(y_true, y_pred, rownames=["True"], colnames=["Predicted"], margins=True))
    print(f"Precision: {precision_score(y_true, y_pred, average='weighted', zero_division=0):.3f}")
    print(f"Recall: {recall_score(y_true, y_pred, average='weighted', zero_division=0):.3f}")
    print(f"F1-measure: {f1_score(y_true, y_pred, average='weighted', zero_division=0):.3f}")
    print("\nClassification report")
    print(classification_report(y_true, y_pred, target_names=class_names, zero_division=0))


def run_cross_validation(model, X_data, y_data, name):
    print(f"===== Cross Validation: {name} =====")
    scores = cross_val_score(model, X_data, y_data, cv=cv, scoring="accuracy")
    print("Scores:", scores)
    print("Mean Accuracy: %.4f" % scores.mean())
    print("Std Dev: %.4f" % scores.std())
    print()


def evaluate_roc_auc(model, X_train, X_test, y_train, y_test, class_names, name):
    """
    Computes multiclass ROC-AUC using One-vs-Rest.
    Requires predict_proba.
    """
    if not hasattr(model, "predict_proba"):
        print(f"ROC/AUC: not available for {name} (predict_proba unsupported)\n")
        return

    model.fit(X_train, y_train)
    y_score = model.predict_proba(X_test)

    y_test_bin = label_binarize(y_test, classes=np.arange(len(class_names)))

    auc_macro_ovr = roc_auc_score(
        y_test_bin,
        y_score,
        multi_class="ovr",
        average="macro",
    )
    auc_weighted_ovr = roc_auc_score(
        y_test_bin,
        y_score,
        multi_class="ovr",
        average="weighted",
    )

    print(f"ROC-AUC macro (OvR): {auc_macro_ovr:.4f}")
    print(f"ROC-AUC weighted (OvR): {auc_weighted_ovr:.4f}")
    print()


def print_feature_importance(fitted_model, feature_names, top_n=10):
    """
    Works for tree-based models with feature_importances_.
    """
    classifier = fitted_model
    if hasattr(fitted_model, "named_steps"):
        classifier = list(fitted_model.named_steps.values())[-1]

    if not hasattr(classifier, "feature_importances_"):
        print("Feature importance: not available for this model.\n")
        return

    importances = classifier.feature_importances_
    importance_df = pd.DataFrame({
        "Feature": feature_names,
        "Importance": importances
    }).sort_values(by="Importance", ascending=False)

    print("Top feature importances")
    print(importance_df.head(top_n).to_string(index=False))
    print()


# ============================================================
# Define models
# ============================================================

models = {
    "Logistic Regression": Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(max_iter=1000, random_state=RANDOM_STATE))
    ]),
    "Random Forest": Pipeline([
        ("clf", RandomForestClassifier(random_state=RANDOM_STATE))
    ]),
    "Decision Tree": Pipeline([
        ("clf", DecisionTreeClassifier(random_state=RANDOM_STATE))
    ]),
    "Naive Bayes": Pipeline([
        ("scaler", StandardScaler()),
        ("clf", GaussianNB())
    ]),
}

# ============================================================
# Train / Test Evaluation + Cross Validation + ROC/AUC
# ============================================================

for name, model in models.items():
    print("#" * 24, name, "#" * 24)

    # Fit on hold-out training set
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)

    # Standard metrics
    print_stats_metrics(y_test, predictions, class_names)

    # Cross-validation
    run_cross_validation(model, X, y_encoded, name)

    # ROC/AUC
    evaluate_roc_auc(model, x_train, x_test, y_train, y_test, class_names, name)

    # Feature importance for tree-based methods
    if name in {"Random Forest", "Decision Tree"}:
        print_feature_importance(model, feature_names, top_n=10)

print("Done.")