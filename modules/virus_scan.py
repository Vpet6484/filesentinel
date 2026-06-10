import subprocess
import os

CLAMSCAN_PATH = r"C:\Program Files\ClamAV\clamscan.exe"


def scan_file(path):

    try:
        if not os.path.exists(path):
            return "error", "File not found"

        result = subprocess.run(
            [CLAMSCAN_PATH, path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False
        )

        output = result.stdout

        # If virus found
        if "FOUND" in output:
            virus = output.split(":")[-1].replace("FOUND", "").strip()
            return "infected", virus

        return "clean", None

    except Exception as e:
        return "error", str(e)
