
# Python libraries
from dotenv import load_dotenv
import os
import re
import shutil
from pathlib import Path

load_dotenv()
## Below are RAG specific libraries

from langchain_community.document_loaders import PyPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAIEmbeddings


# -----------------------------------
# Configuration
# -----------------------------------


DATA_FOLDER = "Data" # location where input pdfs are stored
INDEX_ROOT = "indexes" # location where generated FAISS indexes will be saved

# Smaller chunks usually work better for requirements/spec PDFs
CHUNK_SIZE = 300 # Each chunk has 300 characters
CHUNK_OVERLAP = 50 # Each new chunk will overlap the previous chunk by 50 characters


def normalize_version_from_filename(filename: str) -> str:
    """
    Extract version from file name.
    Example:
        Fortify_Sys_Reqs_18.20.pdf -> 18.20
        Fortify_Sys_Reqs_24.20.pdf -> 24.20
    """
    match = re.search(r"(\d+\.\d+)", filename)
    return match.group(1) if match else "unknown"


def build_index_name(version: str) -> str:
    """
    Example:
        18.20 -> faiss_index_18_20
    """
    return f"faiss_index_{version.replace('.', '_')}"


def clean_text(value: str) -> str:
    """
    Optional cleanup for noisy whitespace.
    """
    return " ".join(value.split())


def detect_product_from_text(text: str) -> str:
    """
    Detect Fortify product from page text
    """
    t = text.lower()

    if "source code analyzer" in t or "fortify sca" in t:
        return "Source Code Analyzer"

    if "software security center" in t or "fortify ssc" in t:
        return "Software Security Center"

    if "scancentral" in t:
        return "ScanCentral"

    return "unknown"


def main():
    data_path = Path(DATA_FOLDER)
    index_root = Path(INDEX_ROOT)

    if not data_path.exists():
        raise FileNotFoundError(f"Data folder not found: {DATA_FOLDER}")

    pdf_files = sorted([p for p in data_path.iterdir() if p.suffix.lower() == ".pdf"])

    if not pdf_files:
        raise FileNotFoundError(f"No PDF files found inside: {DATA_FOLDER}")

    print(f"Found {len(pdf_files)} PDF file(s).")

    embeddings = OpenAIEmbeddings()

    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP
    )

    # Recreate index root fresh
    if index_root.exists():
        shutil.rmtree(index_root)
    index_root.mkdir(parents=True, exist_ok=True)

    summary = []

    for pdf_path in pdf_files:
        filename = pdf_path.name
        version = normalize_version_from_filename(filename)
        index_name = build_index_name(version)
        index_path = index_root / index_name

        print(f"\nProcessing: {filename}")
        print(f"Detected version: {version}")

        loader = PyPDFLoader(str(pdf_path))
        docs = loader.load()

        # Add explicit metadata to each page
        for doc in docs:
            doc.page_content = clean_text(doc.page_content)
            
            #detected_product = detect_product_from_text(doc.page_content)
            doc.metadata["source"] = filename
            doc.metadata["version"] = version
            
            #doc.metadata["product"] = "Fortify SCA"

        chunks = text_splitter.split_documents(docs)

        # Add chunk-level metadata
        for i, chunk in enumerate(chunks, start=1):
            chunk.metadata["chunk_id"] = i
            chunk.metadata["product"] = detect_product_from_text(chunk.page_content)
            

        vector_store = FAISS.from_documents(chunks, embeddings)
        vector_store.save_local(str(index_path))

        print(f"Pages loaded : {len(docs)}")
        print(f"Chunks created: {len(chunks)}")
        print(f"Saved index  : {index_path}")

        summary.append(
            {
                "file": filename,
                "version": version,
                "pages": len(docs),
                "chunks": len(chunks),
                "index_path": str(index_path),
            }
        )

    print("\nIngestion completed.\n")
    print("Summary:")
    for item in summary:
        print(
            f"- File: {item['file']} | "
            f"Version: {item['version']} | "
            f"Pages: {item['pages']} | "
            f"Chunks: {item['chunks']} | "
            f"Index: {item['index_path']}"
        )


if __name__ == "__main__":
    main()

