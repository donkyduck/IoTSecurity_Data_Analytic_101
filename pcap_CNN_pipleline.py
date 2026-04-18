import time
from pathlib import Path

import torch
import torch.nn as nn
import torch.optim as optim
from PIL import Image
from sklearn.metrics import classification_report, confusion_matrix
from torch.utils.data import Dataset, DataLoader, random_split
from torchvision import transforms


class PCAPImageDataset(Dataset):
    """
    Load images generated from the previous PCAP-to-image script.

    Expected structure:
    root_dir/
        class_name_1/
            any_subfolder/
                *.png
            *.png
        class_name_2/
            any_subfolder/
                *.png
    """

    def __init__(self, root_dir, image_size=(32, 32)):
        self.root_dir = Path(root_dir)
        self.samples = []

        if not self.root_dir.exists():
            raise FileNotFoundError(f"Dataset root not found: {self.root_dir}")

        self.class_names = sorted(
            [p.name for p in self.root_dir.iterdir() if p.is_dir()]
        )

        if not self.class_names:
            raise ValueError(f"No class folders found in: {self.root_dir}")

        self.class_to_idx = {name: idx for idx, name in enumerate(self.class_names)}

        for class_name in self.class_names:
            class_dir = self.root_dir / class_name

            # Recursively find all PNG files
            for img_path in class_dir.rglob("*.png"):
                self.samples.append((img_path, self.class_to_idx[class_name]))

        if not self.samples:
            raise ValueError(f"No PNG files found in dataset: {self.root_dir}")

        self.transform = transforms.Compose([
            transforms.Grayscale(num_output_channels=1),
            transforms.Resize(image_size),
            transforms.ToTensor(),   # [1, H, W], scaled to [0,1]
        ])

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        img_path, label = self.samples[idx]
        image = Image.open(img_path).convert("L")
        image = self.transform(image)
        return image, label


class IoTCNN(nn.Module):
    """
    Input:  1 x 32 x 32
    Conv1:  32 filters, 5x5 -> 32 x 28 x 28
    Pool1:  2x2            -> 32 x 14 x 14
    Conv2:  64 filters, 5x5 -> 64 x 10 x 10
    Pool2:  2x2            -> 64 x 5 x 5
    FC1:    1600 -> 512
    FC2:    512 -> n_classes
    """

    def __init__(self, n_classes, dropout_p=0.3):
        super().__init__()

        self.features = nn.Sequential(
            nn.Conv2d(1, 32, kernel_size=5, stride=1, padding=0),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(kernel_size=2, stride=2),

            nn.Conv2d(32, 64, kernel_size=5, stride=1, padding=0),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(kernel_size=2, stride=2),
        )

        self.classifier = nn.Sequential(
            nn.Flatten(),
            nn.Linear(64 * 5 * 5, 512),
            nn.ReLU(inplace=True),
            nn.Dropout(dropout_p),
            nn.Linear(512, n_classes)
        )

    def forward(self, x):
        x = self.features(x)
        x = self.classifier(x)
        return x


def train_one_epoch(model, dataloader, criterion, optimizer, device):
    model.train()

    running_loss = 0.0
    correct = 0
    total = 0

    start_time = time.perf_counter()

    for images, labels in dataloader:
        images = images.to(device)
        labels = labels.to(device)

        optimizer.zero_grad()

        outputs = model(images)
        loss = criterion(outputs, labels)

        loss.backward()
        optimizer.step()

        running_loss += loss.item() * images.size(0)
        preds = outputs.argmax(dim=1)
        correct += (preds == labels).sum().item()
        total += labels.size(0)

    end_time = time.perf_counter()

    epoch_loss = running_loss / total if total > 0 else 0.0
    epoch_acc = correct / total if total > 0 else 0.0
    epoch_runtime = end_time - start_time

    return epoch_loss, epoch_acc, epoch_runtime


@torch.no_grad()
def evaluate(model, dataloader, criterion, device):
    model.eval()

    running_loss = 0.0
    correct = 0
    total = 0

    all_labels = []
    all_preds = []

    start_time = time.perf_counter()

    for images, labels in dataloader:
        images = images.to(device)
        labels = labels.to(device)

        outputs = model(images)
        loss = criterion(outputs, labels)

        running_loss += loss.item() * images.size(0)
        preds = outputs.argmax(dim=1)

        correct += (preds == labels).sum().item()
        total += labels.size(0)

        all_labels.extend(labels.cpu().numpy().tolist())
        all_preds.extend(preds.cpu().numpy().tolist())

    end_time = time.perf_counter()

    loss_avg = running_loss / total if total > 0 else 0.0
    acc = correct / total if total > 0 else 0.0
    runtime = end_time - start_time

    return loss_avg, acc, runtime, all_labels, all_preds


def fit_model(model, train_loader, val_loader, class_names, epochs=10, lr=0.001):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = model.to(device)

    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=lr)

    print(f"Using device: {device}")

    total_start = time.perf_counter()

    for epoch in range(epochs):
        train_loss, train_acc, train_time = train_one_epoch(
            model, train_loader, criterion, optimizer, device
        )
        val_loss, val_acc, val_time, _, _ = evaluate(
            model, val_loader, criterion, device
        )

        print(
            f"Epoch {epoch+1:02d}/{epochs} | "
            f"Train Loss: {train_loss:.4f} | Train Acc: {train_acc:.4f} | Train Time: {train_time:.4f}s | "
            f"Val Loss: {val_loss:.4f} | Val Acc: {val_acc:.4f} | Val Time: {val_time:.4f}s"
        )

    total_end = time.perf_counter()
    print(f"Total training runtime: {total_end - total_start:.4f} seconds")

    # Final evaluation report
    val_loss, val_acc, val_time, y_true, y_pred = evaluate(
        model, val_loader, criterion, device
    )

    print("\nFinal Validation Results")
    print(f"Val Loss: {val_loss:.4f}")
    print(f"Val Acc : {val_acc:.4f}")
    print(f"Val Time: {val_time:.4f}s")

    print("\nConfusion Matrix")
    print(confusion_matrix(y_true, y_pred))

    print("\nClassification Report")
    print(classification_report(y_true, y_pred, target_names=class_names, digits=4))

    return model


def create_dataloaders(dataset_root, batch_size=32, train_ratio=0.8, random_seed=42):
    dataset = PCAPImageDataset(dataset_root, image_size=(32, 32))

    total_size = len(dataset)
    train_size = int(train_ratio * total_size)
    val_size = total_size - train_size

    generator = torch.Generator().manual_seed(random_seed)
    train_set, val_set = random_split(dataset, [train_size, val_size], generator=generator)

    train_loader = DataLoader(train_set, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_set, batch_size=batch_size, shuffle=False)

    return dataset, train_loader, val_loader


if __name__ == "__main__":
    DATASET_ROOT = "/Users/nstda/Documents/GitHub/IoTSecurity_Data_Analytic_101/CNNimage"

    dataset, train_loader, val_loader = create_dataloaders(
        dataset_root=DATASET_ROOT,
        batch_size=32,
        train_ratio=0.8,
        random_seed=42
    )

    print(f"Classes: {dataset.class_names}")
    print(f"Total images: {len(dataset)}")

    model = IoTCNN(n_classes=len(dataset.class_names), dropout_p=0.3)

    fit_model(
        model=model,
        train_loader=train_loader,
        val_loader=val_loader,
        class_names=dataset.class_names,
        epochs=10,
        lr=0.001
    )