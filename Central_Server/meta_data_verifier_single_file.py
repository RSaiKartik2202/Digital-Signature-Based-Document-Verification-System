import os
import sys
from PyPDF2 import PdfReader

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

def main():
    if len(sys.argv)!= 2:
        print("Usage: python script.py <pdf_file>")
        sys.exit(1)

    file_name = sys.argv[1]
    extract_metadata_from_pdf(file_name)

if __name__ == '__main__':
    main()
