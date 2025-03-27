import os
import sys
from PyPDF2 import PdfReader, PdfWriter
from pathlib import Path

def append_metadata_to_pdf(pdf_file, output_pdf_file):
    reader = PdfReader(pdf_file)
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)
    
    metadata = {
        '/Title': 'Signed PDF Document',
        '/UniqueID': os.path.basename(pdf_file),  # Storing file name as Unique ID
        '/Organization': 'NIT Warangal'
    }

    writer.add_metadata(metadata)

    with open(output_pdf_file, 'wb') as output_pdf:
        writer.write(output_pdf)

    print(f"Metadata added successfully! Saved as {output_pdf_file}")

def process_pdfs_in_directory(input_dir, output_dir):
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    for pdf_file in input_path.glob("*.pdf"):
        output_pdf_file = output_path / f"signed_{pdf_file.name}"
        append_metadata_to_pdf(pdf_file, output_pdf_file)

def main():
    input_directory = "unsigned_documents"  # Directory containing unsigned PDFs
    output_directory = "signed_documents"  # Directory to save signed PDFs
    process_pdfs_in_directory(input_directory, output_directory)

if __name__ == '__main__':
    main()
