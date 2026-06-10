from openpyxl import load_workbook
import tempfile


# ==================================================
# XLSX WATERMARK USING CORE METADATA
# ==================================================

def embed_xlsx(src_path, token):

    wb = load_workbook(src_path)

    props = wb.properties

    # Use keywords (stable)
    props.keywords = token


    temp_path = tempfile.mktemp(suffix=".xlsx")

    wb.save(temp_path)

    return temp_path
