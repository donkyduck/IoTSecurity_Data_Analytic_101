from warnings import simplefilter

import numpy as np
import pandas as pd
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

simplefilter(action='ignore', category=FutureWarning)

print("Begin:__________________________________")

# Load CSV with pandas for safer parsing
df = pd.read_csv("label_feature_IOT.csv")

# Column 0 = label, columns 1..18 = features
target = df.iloc[:, 0].astype(str)
feature = df.iloc[:, 1:19].copy()

# Convert last 5 columns from hex to int
for c in feature.columns[-5:]:
    feature[c] = feature[c].apply(lambda x: int(str(x), 16))

# Convert features to numpy
X = feature.values
y = LabelEncoder().fit_transform(target)

# Standardization
X_std = StandardScaler().fit_transform(X)

# Train/test split
x_train, x_test, y_train, y_test = train_test_split(
    X_std, y, test_size=0.25, random_state=0, stratify=y
)

def print_stats_metrics(y_test, y_pred):
    print('Accuracy: %.2f' % accuracy_score(y_test, y_pred))
    confmat = confusion_matrix(y_true=y_test, y_pred=y_pred)
    print("confusion matrix")
    print(confmat)
    print(pd.crosstab(y_test, y_pred, rownames=['True'], colnames=['Predicted'], margins=True))
    print('Precision: %.3f' % precision_score(y_true=y_test, y_pred=y_pred, average='weighted', zero_division=0))
    print('Recall: %.3f' % recall_score(y_true=y_test, y_pred=y_pred, average='weighted', zero_division=0))
    print('F1-measure: %.3f' % f1_score(y_true=y_test, y_pred=y_pred, average='weighted', zero_division=0))
    print()

# Logistic Regression
print("######################## Logistic Regression ########################")
clfLog = LogisticRegression(max_iter=1000, random_state=0)
clfLog.fit(x_train, y_train)
predictions = clfLog.predict(x_test)
print_stats_metrics(y_test, predictions)

# Random Forest
print("######################## Random Forest ########################")
clfRandForest = RandomForestClassifier(random_state=0)
clfRandForest.fit(x_train, y_train)
predictions = clfRandForest.predict(x_test)
print_stats_metrics(y_test, predictions)

# Decision Tree
print("######################## Decision Tree ########################")
clfDT = DecisionTreeClassifier(random_state=0)
clfDT.fit(x_train, y_train)
predictions = clfDT.predict(x_test)
print_stats_metrics(y_test, predictions)

# Naive Bayes
print("######################## Naive Bayes ########################")
clfNB = GaussianNB()
clfNB.fit(x_train, y_train)
predictions = clfNB.predict(x_test)
print_stats_metrics(y_test, predictions)