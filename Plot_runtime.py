import matplotlib.pyplot as plt
import numpy as np

# Data
models = ["LogReg", "RandForest", "DecTree", "NaiveBayes"]

train_times = [0.129383, 0.338501, 0.006776, 0.001795]
predict_times = [0.001103, 0.012386, 0.000181, 0.002684]
f1_scores = [0.905, 1.0, 1.0, 0.861]

# =========================
# 1. Bar Chart: Runtime
# =========================
x = np.arange(len(models))
width = 0.35

plt.figure(figsize=(8,5))

plt.bar(x - width/2, train_times, width, label="Training Time")
plt.bar(x + width/2, predict_times, width, label="Prediction Time")

plt.xticks(x, models)
plt.xlabel("Models")
plt.ylabel("Time (seconds)")
plt.title("ML Model Runtime Comparison")

# Log scale (important for visibility)
plt.yscale("log")

plt.legend()
plt.grid(axis='y', linestyle='--', alpha=0.6)

plt.tight_layout()
plt.show()

# =========================
# 2. Scatter: Performance vs Runtime
# =========================
plt.figure(figsize=(7,5))

plt.scatter(train_times, f1_scores)

for i, model in enumerate(models):
    plt.text(train_times[i]*1.05, f1_scores[i], model)

plt.xlabel("Training Time (seconds)")
plt.ylabel("F1 Score")
plt.title("Performance vs Runtime Trade-off")

plt.grid(True, linestyle='--', alpha=0.6)

plt.tight_layout()
plt.show()