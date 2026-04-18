from warnings import simplefilter
import time

import numpy as np
import pandas as pd
from numpy import genfromtxt
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, confusion_matrix, f1_score,
    precision_score, recall_score
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

simplefilter(action='ignore', category=FutureWarning)

program_start = time.perf_counter()

print("Begin:__________________________________")

# ===================== Load data =====================
data_start = time.perf_counter()

feature = genfromtxt(
    'label_feature_IOT.csv',
    delimiter=',',
    usecols=(i for i in range(1, 19)),
    dtype=int,
    skip_header=1
)
target = genfromtxt(
    'label_feature_IOT.csv',
    delimiter=',',
    usecols=(0),
    dtype=str,
    skip_header=1
)

for c in range(-5, 0):
    for i in range(len(feature[:, c])):
        feature[:, c][i] = int(str(feature[:, c][i]), 16)

labels = LabelEncoder().fit_transform(target)
feature_std = StandardScaler().fit_transform(feature)
x_train, x_test, y_train, y_test = train_test_split(
    feature_std, labels, test_size=0.25, random_state=0
)

data_end = time.perf_counter()
print(f"Data preparation runtime: {data_end - data_start:.6f} seconds")


def print_stats_metrics(y_test, y_pred):
    print('Accuracy: %.2f' % accuracy_score(y_test, y_pred))
    confmat = confusion_matrix(y_true=y_test, y_pred=y_pred)
    print("confusion matrix")
    print(confmat)
    print(pd.crosstab(y_test, y_pred, rownames=['True'], colnames=['Predicted'], margins=True))
    print('Precision: %.3f' % precision_score(y_true=y_test, y_pred=y_pred, average='weighted'))
    print('Recall: %.3f' % recall_score(y_true=y_test, y_pred=y_pred, average='weighted'))
    print('F1-measure: %.3f' % f1_score(y_true=y_test, y_pred=y_pred, average='weighted'))


# ===================== Logistic Regression =====================
print("######################## Logistic Regression ########################")
clfLog = LogisticRegression(max_iter=1000)

train_start = time.perf_counter()
clfLog.fit(x_train, y_train)
train_end = time.perf_counter()

pred_start = time.perf_counter()
predictions = clfLog.predict(x_test)
pred_end = time.perf_counter()

print_stats_metrics(y_test, predictions)
print(f"Training runtime:  {train_end - train_start:.6f} seconds")
print(f"Prediction runtime:{pred_end - pred_start:.6f} seconds")


# ===================== Random Forest =====================
print("######################## Random Forest ########################")
clfRandForest = RandomForestClassifier(random_state=0)

train_start = time.perf_counter()
clfRandForest.fit(x_train, y_train)
train_end = time.perf_counter()

pred_start = time.perf_counter()
predictions = clfRandForest.predict(x_test)
pred_end = time.perf_counter()

print_stats_metrics(y_test, predictions)
print(f"Training runtime:  {train_end - train_start:.6f} seconds")
print(f"Prediction runtime:{pred_end - pred_start:.6f} seconds")


# ===================== Decision Tree =====================
print("######################## Decision Tree ########################")
clfDT = DecisionTreeClassifier(random_state=0)

train_start = time.perf_counter()
clfDT.fit(x_train, y_train)
train_end = time.perf_counter()

pred_start = time.perf_counter()
predictions = clfDT.predict(x_test)
pred_end = time.perf_counter()

print_stats_metrics(y_test, predictions)
print(f"Training runtime:  {train_end - train_start:.6f} seconds")
print(f"Prediction runtime:{pred_end - pred_start:.6f} seconds")


# ===================== Naive Bayes =====================
print("######################## Naive Bayes ########################")
clfNB = GaussianNB()

train_start = time.perf_counter()
clfNB.fit(x_train, y_train)
train_end = time.perf_counter()

pred_start = time.perf_counter()
predictions = clfNB.predict(x_test)
pred_end = time.perf_counter()

print_stats_metrics(y_test, predictions)
print(f"Training runtime:  {train_end - train_start:.6f} seconds")
print(f"Prediction runtime:{pred_end - pred_start:.6f} seconds")


program_end = time.perf_counter()
print(f"Total program runtime: {program_end - program_start:.6f} seconds")