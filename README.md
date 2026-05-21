
Domain explanation -
  
  The domain is about Fortify software installation requirements. Fortify is a tool used to identify different types of security violations in code. Inorder to scan the code we need to first setup the software.
  I have downloaded 4 different versions of the system requirements which are pdfs available in public and implemented chatbot to answer questions
  
Public data source links - 
https://www.microfocus.com/documentation/fortify-core-documents/2420/Fortify_Sys_Reqs_24.2.0/index.htm
https://www.microfocus.com/documentation/fortify-core-documents/2320/Fortify_Sys_Reqs_23.2.0/index.htm
https://www.microfocus.com/documentation/fortify-software-security-center/2120/Fortify_Sys_Reqs_21.2.0/index.htm
https://www.microfocus.com/documentation/fortify-software-security-center/1820/Fortify_Sys_Reqs_Help_18.20/index.htm



Setup - I have downloaded the documents into Data folder and code architecture has been explained below
Usage - The documents have information regarding different tools in each version. The hardware requirements and databases supported change from version to version. The chatbot would answer questions regarding the same.


RAG-Based Fortify Requirements Chatbot

A Retrieval-Augmented Generation (RAG) chatbot that answers questions from Fortify System Requirements PDFs across multiple versions and products.

The chatbot retrieves relevant document chunks using FAISS and generates answers strictly from retrieved content.

Features
Retrieval-Augmented Generation (RAG)
No fine-tuning used
No hard-coded answers
LLM responses grounded in retrieved chunks
Uses FAISS vector search
Multi-Version Support

Supports multiple Fortify versions:

18.2
21.2
23.2
24.2

Each version has its own FAISS index.

Example:

List databases supported in Fortify SCA 18.2
Multi-Product Support

Supports multiple Fortify products:

Fortify SCA (Source Code Analyzer)
Fortify SSC (Software Security Center)
ScanCentral SAST

Example:

List hardware requirements for Fortify SSC 23.2
Context Awareness (Conversation Memory)

Supports follow-up questions:

List OS supported for Fortify SCA 24.2
Is it same for 21.2
What about databases

The chatbot remembers:

version
product
topic
Version Comparison

Supports comparison across versions:

List OS supported for Fortify SCA 24.2
Is it same for 18.2

The chatbot retrieves both versions and compares.

Topic-Aware Retrieval

Automatically detects topics:

platforms
databases
hardware
software
build tools
Java
application servers

Example:

Which Java versions does Fortify SCA 21.2 support
Multi-Stage Retrieval Pipeline

The chatbot uses three retrieval stages:

Stage 1 — Vector Retrieval

Top-k similarity search using FAISS

Stage 2 — Broader Retrieval

Multiple expanded search queries

Stage 3 — Keyword Scan

Fallback scan across all chunks

This improves recall and reduces missed answers.

Safety & Accuracy

If answer is not found:

I don't have enough information in the provided documents.

Prevents hallucinations.

Project Structure
project/
│
├── Data/
│   ├── Fortify_Sys_Reqs_18.20.pdf
│   ├── Fortify_Sys_Reqs_21.20.pdf
│   ├── Fortify_Sys_Reqs_23.20.pdf
│   └── Fortify_Sys_Reqs_24.20.pdf
│
├── indexes/
│   ├── faiss_index_18_20/
│   ├── faiss_index_21_20/
│   ├── faiss_index_23_20/
│   └── faiss_index_24_20/
│
├── ingest.py
├── chatbot.py
├── .env
└── README.md
Installation
Install dependencies
pip install langchain
pip install langchain-community
pip install langchain-openai
pip install faiss-cpu
pip install python-dotenv
pip install pypdf
Environment Setup

Create .env file:

OPENAI_API_KEY=your_api_key_here
Ingest Documents

Run:

python ingest.py

This:

loads PDFs
splits into chunks
adds metadata
builds FAISS index
stores per version
Run Chatbot
python chatbot.py
Example Questions
Single version
List databases supported in Fortify SCA 18.2
Follow-up
Does it support Oracle
Comparison
List OS supported for Fortify SCA 24.2
Is it same for 18.2
Product specific
List hardware requirements for Fortify SSC 23.2
RAG Pipeline
User Question
      ↓
Detect version
Detect product
Detect topic
      ↓
Load version FAISS index
      ↓
Stage 1: vector retrieval
      ↓
Stage 2: broader retrieval
      ↓
Stage 3: keyword scan
      ↓
docs_to_context()
      ↓
LLM grounded response
Constraints
No fine-tuning
No hard-coded answers
Retrieval drives response
LLM does not answer from memory
Safe fallback if not found
Technologies Used
LangChain
FAISS
OpenAI embeddings
Python
RecursiveCharacterTextSplitter
PyPDFLoader
