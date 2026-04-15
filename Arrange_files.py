import shutil
from pathlib import Path

# Source and destination folders
SOURCE_DIR = Path.home() / "Downloads/data/pcap/"
DEST_DIR = Path.home() / "/Users/nstda/Documents/Keio_Cyber/EL_pcap_files/Turn_onff_SharpApp"

# Create destination if not exists
DEST_DIR.mkdir(parents=True, exist_ok=True)

# Move files
for file in SOURCE_DIR.iterdir():
    if file.is_file() and file.name.startswith("Turn_onff_SharpApp_"):
        dest_path = DEST_DIR / file.name
        print(f"[MOVE] {file} -> {dest_path}")
        shutil.move(str(file), str(dest_path))

print("Done.")