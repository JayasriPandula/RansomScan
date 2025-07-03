import os

# Base path inside your venv for simulation
base_path = r"C:\Users\jayas\code folder\code folder\venv\test_ransomware"

# Make a test folder if it doesn't exist
os.makedirs(base_path, exist_ok=True)

# Create dummy files and simulate "encryption"
for i in range(5):
    filename = os.path.join(base_path, f"document_{i}.txt")
    with open(filename, "w") as f:
        f.write("This is a test document. Ransomware simulation only.")
    
    # Rename to mimic ransomware-encrypted file
    os.rename(filename, filename + ".locked")

# Add a fake ransom note
note_path = os.path.join(base_path, "README_RESTORE_FILES.txt")
with open(note_path, "w") as note:
    note.write("Your files have been encrypted. Pay 0 BTC to nobody. This is a simulation.")

print("Fake ransomware simulation complete.")
print("Files are located at:", base_path)
