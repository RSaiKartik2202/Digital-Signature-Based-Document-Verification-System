import os
import sys
from PyPDF2 import PdfReader
from pathlib import Path

def extract_metadata_from_pdf(pdf_file):
    if not os.path.exists(pdf_file):
        print(f"Error: File `{pdf_file}` not found.")
        return
    
    reader = PdfReader(pdf_file)
    metadata = reader.metadata

    print(f"\nExtracted Metadata from: {pdf_file}")
    print(f"Unique ID:{metadata.get('/UniqueID', 'N/A')}")
    print(f"Organization:{metadata.get('/Organization', 'N/A')}")
    print("-" * 50)

def extract_metadata_from_directory(directory):
    dir_path = Path(directory)
    if not dir_path.exists() or not dir_path.is_dir():
        print(f"Error: Directory `{directory}` not found.")
        return
    
    for pdf_file in dir_path.glob("*.pdf"):
        extract_metadata_from_pdf(pdf_file)

def main():
    directory = "signed_documents"
    extract_metadata_from_directory(directory)

if __name__ == '__main__':
    main()