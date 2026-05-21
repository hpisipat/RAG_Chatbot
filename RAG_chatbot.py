
from dotenv import load_dotenv

import os
import re
from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
load_dotenv()


# -------------------------
# Configuration
# -------------------------
INDEX_ROOT = "indexes"  ## This tells chatbot where saved indexes are stored

# This maps the version wording a user types to the version format used in your filenames and index folders.
VERSION_MAP = {
    "18.2": "18.20",
    "24.2": "24.20",
    "21.2": "21.20",
    "23.2": "23.20"
}

PRODUCT_MAP = {
    "source code analyzer": "Source Code Analyzer",
    "sca": "Source Code Analyzer",
    "software security center": "Software Security Center",
    "ssc": "Software Security Center",
    "scancentral sasti": "ScanCentral SAST",
    "scancentral": "ScanCentral SAST",
}


TOPIC_KEYWORDS = {
    "platforms": ["platform", "platforms", "os", "operating system"],
    "databases": ["database", "databases", "oracle", "mysql", "sql", "sql server"],
    "hardware": ["hardware", "ram", "memory", "processor", "cpu", "cores"],
    "software": ["software", "software requirements", "prerequisite", "prerequisites", "requirements"],
    "application server" : ["application server","application servers","tomcat"],
    "build tools" : ["build tool","build tools","maven","gradle", "Ant","Bamboo"],
    "java" : ["java","Java","jdk", "JDK","jre","JRE"]
    
	
}

SAFE_FALLBACK = "I don't have enough information in the provided documents."


# -------------------------
# Helpers
# -------------------------

# This function decides which Fortify version the user is asking about.
def detect_version(query: str, current_version: str | None) -> str | None:
    q_lower = query.lower()

    for user_version, internal_version in VERSION_MAP.items():
        if user_version in q_lower:
            return internal_version

    if "this version" in q_lower or "that version" in q_lower:
        return current_version

    return current_version

# This function decides the current topic of the conversation.
def detect_topic(query: str, current_topic: str | None) -> str | None:
    q_lower = query.lower()

    for topic, keywords in TOPIC_KEYWORDS.items():
        for word in keywords:
            if word in q_lower:
                return topic

    if "what about" in q_lower or "how about" in q_lower or "does it support" in q_lower:
        return current_topic

    return current_topic


#
def detect_product(query: str, current_product: str | None) -> str | None:
    q = query.lower()

    if "source code analyzer" in q or "sca" in q:
        return "Source Code Analyzer"

    if "software security center" in q or "ssc" in q:
        return "Software Security Center"

    if "scancentral" in q:
        return "ScanCentral"

    if "this product" in q or "that product" in q:
        return current_product

    return current_product


# This builds the folder path for the FAISS index belonging to the selected version.
def get_index_path(version: str | None) -> str | None:
    if not version:
        return None
    return os.path.join(INDEX_ROOT, f"faiss_index_{version.replace('.', '_')}")

# This builds the main search query that is sent to the retriever.
def build_retrieval_query(user_query: str, version: str | None, topic: str | None, product: str | None) -> str:
    parts = []

    if product:
        parts.append(product)

    if version:
        parts.append(version)

    if topic == "platforms":
        parts.append("supported platforms operating systems")
    elif topic == "databases":
        parts.append("supported databases")
    elif topic == "hardware":
        parts.append("hardware requirements RAM memory processor CPU cores")
    elif topic == "software":
        parts.append("software requirements prerequisites supported software")
    elif topic == "build tools":
        parts.append("supported build tools maven gradle ant bamboo xcodebuild msbuild")
    elif topic == "java":
        parts.append("supported Java versions JDK JRE Android")
    elif topic == "application server":
        parts.append("supported application servers tomcat websphere weblogic")
    else:
        parts.append(user_query)

    return " ".join(parts)


# This builds the main search query that is sent to the retriever.
def build_broader_queries(user_query: str, version: str | None, topic: str | None, product: str | None) -> list[str]:
    base = []
    if product:
        base.append(product)
    if version:
        base.append(version)

    prefix = " ".join(base)
    queries = []

    if topic == "platforms":
        queries.append(f"{prefix} supported platforms")
        queries.append(f"{prefix} operating systems")
        queries.append(f"{prefix} system requirements platforms")

    elif topic == "databases":
        queries.append(f"{prefix} supported databases")
        queries.append(f"{prefix} Oracle MySQL SQL Server")
        queries.append(f"{prefix} database requirements")

    elif topic == "hardware":
        queries.append(f"{prefix} hardware requirements")
        queries.append(f"{prefix} RAM memory CPU processor")
        queries.append(f"{prefix} performance requirements")

    elif topic == "software":
        queries.append(f"{prefix} software requirements")
        queries.append(f"{prefix} prerequisites")
        queries.append(f"{prefix} supported software")

    elif topic == "build tools":
        queries.append(f"{prefix} supported build tools")
        queries.append(f"{prefix} maven gradle ant bamboo xcodebuild msbuild")
        queries.append(f"{prefix} build integration tools")

    elif topic == "java":
        queries.append(f"{prefix} supported Java versions")
        queries.append(f"{prefix} JDK JRE Android support")
        queries.append(f"{prefix} Java requirements")
    elif topic == "application server":
        queries.append(f"{prefix} supported application servers")
        queries.append(f"{prefix} tomcat websphere weblogic")
        queries.append(f"{prefix} application server requirements")

    else:
        queries.append(f"{prefix} {user_query}".strip())
        queries.append(f"{prefix} system requirements".strip())

    return queries

# This loads a FAISS index from disk.
def load_vector_store(index_path: str, embeddings):
    return FAISS.load_local(
        index_path,
        embeddings,
        allow_dangerous_deserialization=True
    )

# This removes duplicate chunks from retrieval results.
def dedupe_docs(docs):
    seen = set()
    unique = []

    for doc in docs:
        source = doc.metadata.get("source", "")
        page = doc.metadata.get("page", "")
        chunk_id = doc.metadata.get("chunk_id", "")
        key = (source, page, chunk_id, doc.page_content[:120])

        if key not in seen:
            seen.add(key)
            unique.append(doc)

    return unique

# This prepares keywords for the all-chunk keyword scan.
def extract_keywords(query: str, topic: str | None) -> list[str]:
    words = re.findall(r"\b[a-zA-Z0-9\.\-]+\b", query.lower())

    stop_words = {
        "the", "is", "are", "a", "an", "of", "for", "to", "does", "it",
        "what", "about", "which", "in", "this", "that", "support", "supported",
        "fortify", "sca", "version"
    }

    keywords = [w for w in words if w not in stop_words and len(w) > 2]

    if topic == "databases":
        keywords.extend(["database", "oracle", "mysql", "sql", "server"])
    elif topic == "platforms":
        keywords.extend(["platform", "platforms", "operating", "system", "linux", "windows", "macos"])

    # preserve order, remove duplicates
    final_keywords = []
    seen = set()
    for kw in keywords:
        if kw not in seen:
            seen.add(kw)
            final_keywords.append(kw)

    return final_keywords

# This is one of the most important safety features.
def keyword_scan_all_chunks(vector_store, query: str, topic: str | None, max_docs: int = 8):
    """
    Scan all chunk texts in the currently selected version index.
    This is a fallback when retrieval misses the right chunk.
    """
    keywords = extract_keywords(query, topic)

    all_docs = list(vector_store.docstore._dict.values())  # practical for local project use
    scored = []

    for doc in all_docs:
        text = doc.page_content.lower()
        score = sum(1 for kw in keywords if kw in text)

        if score > 0:
            scored.append((score, doc))

    scored.sort(key=lambda x: x[0], reverse=True)
    matched_docs = [doc for _, doc in scored[:max_docs]]

    return matched_docs

# This converts a list of retrieved chunks into one big text block for the LLM prompt.
def docs_to_context(docs):
    return "\n\n".join(
        f"Source: {doc.metadata.get('source', 'Unknown')}\n"
        f"Page: {doc.metadata.get('page', 'Unknown')}\n"
        f"{doc.page_content}"
        for doc in docs
    )

# This is the final answer-generation step.
def ask_llm(llm, query: str, selected_version: str, last_topic: str | None, context: str, chat_history: list[str]):
    conversation_context = "\n".join(chat_history[-6:])

    prompt = f"""
You are a retrieval-based assistant answering questions from the provided Fortify requirement documents.

Conversation history:
{conversation_context}

Current version:
{selected_version}

Current topic:
{last_topic}

Instructions:
- If comparing versions, explicitly state whether they are the same or different.
- Answer ONLY using the retrieved context below.
- Do NOT use your own general knowledge.
- Do NOT guess or fill gaps.
- If the retrieved context does not clearly contain the answer, reply exactly:
  "{SAFE_FALLBACK}"
- Retrieval must drive the response.

Retrieved Context:
{context}

Question:
{query}
"""

    response = llm.invoke(prompt)
    return response.content.strip()

# This prints the unique source file names for the retrieved chunks.
def print_sources(docs):
    unique_sources = sorted({doc.metadata.get("source", "Unknown") for doc in docs})
    print("\nUsing source:", ", ".join(unique_sources))

def is_comparison_query(query: str) -> bool:
    q = query.lower()
    comparison_words = ["same", "different", "compare", "as well", "versus", "vs"]
    return any(word in q for word in comparison_words)

# -------------------------
# Main
# -------------------------
embeddings = OpenAIEmbeddings()
llm = ChatOpenAI(temperature=0)

chat_history = []
selected_version = None
previous_version = None
last_topic = None
current_index_path = None
current_vector_store = None
current_retriever = None
selected_product = None


print("RAG Chatbot ready. Type 'exit' to quit.\n")

# This keeps the chatbot running until the user types exit.
while True:
    query = input("You: ").strip()

    if query.lower() == "exit":
        break

    # This updates conversational state based on the new user input.
    selected_version = detect_version(query, selected_version)
    last_topic = detect_topic(query, last_topic)
    selected_product = detect_product(query, selected_product)

    old_version = previous_version

    if is_comparison_query(query) and old_version and selected_version and old_version != selected_version:
        prev_index_path = get_index_path(old_version)
        curr_index_path = get_index_path(selected_version)

        prev_vector_store = load_vector_store(prev_index_path, embeddings)
        curr_vector_store = load_vector_store(curr_index_path, embeddings)

        prev_retriever = prev_vector_store.as_retriever(search_kwargs={"k": 10})
        curr_retriever = curr_vector_store.as_retriever(search_kwargs={"k": 10})

        prev_docs = prev_retriever.invoke(
            build_retrieval_query(query, old_version, last_topic, selected_product)
        )

        curr_docs = curr_retriever.invoke(
            build_retrieval_query(query, selected_version, last_topic, selected_product)
        )

        prev_docs = dedupe_docs(prev_docs)
        curr_docs = dedupe_docs(curr_docs)

        # Filter by selected product
        if selected_product:
            filtered_prev = [
                d for d in prev_docs
                if selected_product.lower() in d.metadata.get("product", "").lower()
               ]
            if filtered_prev:
                prev_docs = filtered_prev


            filtered_curr = [
                d for d in curr_docs
                if selected_product.lower() in d.metadata.get("product", "").lower()
              ]
           
        
            if filtered_curr:
              curr_docs =  filtered_curr

            

        comparison_context = (
            f"Previous Version ({old_version})\n"
            + docs_to_context(prev_docs[:6])
            + "\n\n"
            f"Current Version ({selected_version})\n"
            + docs_to_context(curr_docs[:6])
        )

        print("Using product:", selected_product)
        print(f"Comparing versions: {old_version} vs {selected_version}")

        answer = ask_llm(
            llm,
            query,
            selected_version,
            last_topic,
            comparison_context,
            chat_history
        )

        print("\nBot:", answer)
        print()

        chat_history.append(f"User: {query}")
        chat_history.append(f"Bot: {answer}")

        previous_version = selected_version
        continue
        
    # If user asks too vaguely, the system does not guess.
    # This is a safety design. It also stores this exchange in chat_history
    if not selected_version:
        answer = "Please mention the Fortify version, for example 18.2 or 24.2."
        print("\nBot:", answer, "\n")
        chat_history.append(f"User: {query}")
        chat_history.append(f"Bot: {answer}")
        continue
    
    # This turns the selected version into the correct FAISS folder path
    # If the folder doesn’t exist, it replies that the index is missing.
    index_path = get_index_path(selected_version)
    if not index_path or not os.path.exists(index_path):
        answer = f"I could not find an index for Fortify {selected_version}."
        print("\nBot:", answer, "\n")
        chat_history.append(f"User: {query}")
        chat_history.append(f"Bot: {answer}")
        continue
    
    # If the user keeps asking about the same version, the chatbot does not reload the index every time.
    # It reloads only when version changes. This improves performance
    # k=8 Normal retrieval returns top 8 chunks.
    if current_index_path != index_path:
        current_vector_store = load_vector_store(index_path, embeddings)
        current_retriever = current_vector_store.as_retriever(search_kwargs={"k": 15})
        current_index_path = index_path

    # -------------------------
    # Stage 1: normal retrieval
    # -------------------------

    # This is the standard RAG retrieval stage.
    retrieval_query = build_retrieval_query(query, selected_version, last_topic, selected_product)
    docs = current_retriever.invoke(retrieval_query)
    docs = dedupe_docs(docs)
    # Filter by selected product
    if selected_product:
        filtered = [
            d for d in docs
            if selected_product.lower() in d.metadata.get("product", "").lower()
        ]

        # only replace if filtering actually found matches
        if filtered:
            docs = filtered

    # -------------------------
    # Stage 2: broader retrieval if needed
    # -------------------------

    # If normal retrieval returns too few chunks, the system assumes retrieval may be weak.
    # Then it tries multiple broader queries
    if len(docs) < 3:
        broader_queries = build_broader_queries(query, selected_version, last_topic,selected_product)
        broader_docs = []

        for bq in broader_queries:
            found = current_vector_store.similarity_search(bq, k=15)
            broader_docs.extend(found)

        docs.extend(broader_docs)
        docs = dedupe_docs(docs)

        if selected_product:
            filtered = [
                d for d in docs
                if selected_product.lower() in d.metadata.get("product", "").lower()
            ]
            if filtered:
                docs = filtered

    # -------------------------
    # Stage 3: keyword scan all chunks if still weak
    # -------------------------

    # If broader semantic retrieval is still weak, the system scans all chunks in the selected version index using keyword overlap.
    if len(docs) < 1:
        keyword_docs = keyword_scan_all_chunks(
            current_vector_store,
            query=query,
            topic=last_topic,
            max_docs=8
        )
        docs.extend(keyword_docs)
        docs = dedupe_docs(docs)

    # If there are still no chunks, the chatbot replies: "I dont have enough information"
    if not docs:
        answer = SAFE_FALLBACK
        print("\nBot:", answer, "\n")
        chat_history.append(f"User: {query}")
        chat_history.append(f"Bot: {answer}")
        continue
    
    # Even after multiple retrieval stages, the system limits the number of chunks passed to the LLM.
    # This helps keep the prompt smaller, avoid overload, reduce noisy context
    print("Using product:", selected_product)
    print_sources(docs[:12])

    context = docs_to_context(docs[:8])
    if not docs or not context.strip():
      answer = SAFE_FALLBACK
    else:
      answer = ask_llm(llm, query, selected_version, last_topic, context, chat_history)

    # -------------------------
    # Optional second-pass safeguard:
    # if LLM says not enough info, try a final all-chunk keyword pass
    # -------------------------
    
    # If the LLM says it still doesn’t have enough information, the code runs one more keyword-based chunk scan with more results:
    # It rebuilds context and asks again
    if answer == SAFE_FALLBACK:
        keyword_docs = keyword_scan_all_chunks(
            current_vector_store,
            query=query,
            topic=last_topic,
            max_docs=12
        )
        keyword_docs = dedupe_docs(keyword_docs)

        if keyword_docs:
            context = docs_to_context(keyword_docs[:10])
            answer = ask_llm(llm, query, selected_version, last_topic, context, chat_history)

    print("\nBot:", answer)
    print()
    
    # shows the answer to the user
    # stores both question and answer for future follow-up handling
    chat_history.append(f"User: {query}")
    chat_history.append(f"Bot: {answer}")

    previous_version = selected_version

