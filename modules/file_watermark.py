import os

from modules.pdf_watermark import embed_pdf
from modules.docx_watermark import embed_docx
from modules.xlsx_watermark import embed_xlsx


def watermark_file(src_path, token):

    ext = os.path.splitext(src_path)[1].lower()

    if ext == ".pdf":
        return embed_pdf(src_path, token)

    elif ext == ".docx":
        return embed_docx(src_path, token)

    elif ext == ".xlsx":
        return embed_xlsx(src_path, token)

    else:
        raise ValueError("Unsupported file type")
