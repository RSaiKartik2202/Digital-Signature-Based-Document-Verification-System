import os
from PyPDF2 import PdfReader

def bytes_to_hex(byte_data):
    return byte_data.hex()

def extract_metadata_from_pdf(pdf_file):
    reader=PdfReader(pdf_file)
    metadata=reader.metadata

    print(f"\nExtracted Metadata from:{pdf_file}")
    print(f"Title:{metadata.get('/Title','N/A')}")
    signature=metadata.get('/Signature','')

    if signature:
        try:
            signature_hex=bytes_to_hex(signature.encode('latin1'))
            print(f"Signature(Hex):{signature_hex}")
        except Exception as e:
            print(f"Error decoding signature:{e}")

    print(f"Unique ID:{metadata.get('/UniqueID','N/A')}")
    print(f"Organization:{metadata.get('/Organization','N/A')}")
    print("-"*50)

def main():
    signed_dir="signed_documents/"

    if not os.path.exists(signed_dir):
        print(f"Error:Directory `{signed_dir}` not found.")
        return

    pdf_files=[f for f in os.listdir(signed_dir) if f.endswith('.pdf')]

    if not pdf_files:
        print("No signed PDF files found in `signed_documents/`.")
        return

    for pdf_file in pdf_files:
        extract_metadata_from_pdf(os.path.join(signed_dir,pdf_file))

if __name__=='__main__':
    main()
