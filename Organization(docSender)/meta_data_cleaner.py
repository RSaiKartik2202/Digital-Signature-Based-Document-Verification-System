import os
from PyPDF2 import PdfReader, PdfWriter
from pathlib import Path

def clear_metadata(pdf_file, output_pdf_file):
    reader = PdfReader(pdf_file)
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)
    
    # Do not add any metadata, effectively removing all existing metadata
    writer.add_metadata({})

    with open(output_pdf_file, 'wb') as output_pdf:
        writer.write(output_pdf)

    print(f"Metadata cleared: {output_pdf_file}")

def clear_metadata_from_directory(input_dir, output_dir):
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    for pdf_file in input_path.glob("*.pdf"):
        output_pdf_file = output_path / pdf_file.name
        clear_metadata(pdf_file, output_pdf_file)

def main():
    input_directory = "pdf_documents"  # Change to your input directory
    output_directory = "cleaned_pdfs"  # Change to your output directory
    clear_metadata_from_directory(input_directory, output_directory)

if __name__ == '__main__':
    main()
