import subprocess
import os
import shutil


def convert_to_pdf(input_path, output_dir):

    soffice = r"C:\Program Files\LibreOffice\program\soffice.exe"

    if not os.path.exists(soffice):
        raise Exception("LibreOffice not found")

    os.makedirs(output_dir, exist_ok=True)

    # 🔐 UNIQUE PROFILE PER CONVERSION (CRITICAL)
    profile_dir = os.path.join(output_dir, "lo_profile")

    # clean old profile if exists
    if os.path.exists(profile_dir):
        shutil.rmtree(profile_dir)

    os.makedirs(profile_dir, exist_ok=True)

    cmd = [
        soffice,
        "--headless",
        "--nologo",
        "--nolockcheck",
        "--norestore",
        f"-env:UserInstallation=file:///{profile_dir.replace(os.sep, '/')}",
        "--convert-to", "pdf:writer_pdf_Export",
        "--outdir", output_dir,
        input_path
    ]

    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:
        print("=== LibreOffice STDOUT ===")
        print(result.stdout)
        print("=== LibreOffice STDERR ===")
        print(result.stderr)
        raise Exception("LibreOffice conversion failed")

    pdf_name = os.path.splitext(os.path.basename(input_path))[0] + ".pdf"
    pdf_path = os.path.join(output_dir, pdf_name)

    if not os.path.exists(pdf_path):
        raise Exception("PDF not created")

    return pdf_path
