from PyPDF2 import PdfReader, PdfWriter
import tempfile
import os


def embed_pdf(src_path, token):

    reader = PdfReader(src_path)
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    # 🔑 SINGLE CANONICAL KEY
    writer.add_metadata({
        "/FileSentinel-Watermark": token
    })

    fd, temp_path = tempfile.mkstemp(suffix=".pdf")
    os.close(fd)

    with open(temp_path, "wb") as f:
        writer.write(f)

    return temp_path
