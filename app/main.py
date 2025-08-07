import os
from fastapi import FastAPI, Request
from contextlib import asynccontextmanager
from pydantic import BaseModel
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.document_loaders import TextLoader
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from langchain_chroma import Chroma
from langchain.prompts import PromptTemplate
from dotenv import load_dotenv

dotenv_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(dotenv_path=dotenv_path)
langchain_api_key = os.getenv("LANGCHAIN_API_KEY")
openai_api_key = os.getenv("OPENAI_API_KEY")
if langchain_api_key:
    os.environ["LANGCHAIN_API_KEY"] = langchain_api_key
if openai_api_key:
    os.environ["OPENAI_API_KEY"] = openai_api_key
os.environ["LANGCHAIN_TRACING_V2"] = "true"


# -----------------------------
# Define the model
# -----------------------------
llm = ChatOpenAI(model="gpt-4.1", temperature=0)

remediate_prompt = PromptTemplate(
    input_variables=["Rules",  "example_rules", "input_code"],
    template="""
You are an SAP ABAP Remediation Expert.
Your task is to fully remediate all forms and subroutines in the ECC ABAP code.
DO NOT skip any section or write placeholders like "...rest is similar".
Comment out old code and insert new code following clean S/4HANA standards.

Apply the following:
- Comment legacy TABLES, OCCURS, LIKE, etc.
- Replace with DATA, TYPES, and modern SELECT.
- Follow all remediation rules strictly.
- Follow syntax and formatting exactly like examples.
- Ensure final output is complete and not trimmed, but do not repeat lines or fields unless they are present multiple times in the input.
- Avoid field duplication in TYPES or DATA definitions.
- Always use global variables as defined in the input to follow the variables in the code.

Rules:
{Rules}



Example Rules:
{example_rules}


ECC ABAP Code:
{input_code}

Output:
[Remediated ABAP Code]
"""
)

# -----------------------------
# Use lifespan instead of @on_event("startup")
# -----------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Loading ruleset and examples into memory...")

    # Load rules once
    ruleset_loader = TextLoader("ruleset.txt")
    rules_docs = ruleset_loader.load()
    app.state.rules_text = "\n\n".join([doc.page_content for doc in rules_docs])

    # Load examples once
    example_loader = TextLoader("abap_program.txt")
    example_docs = example_loader.load()
    app.state.example_rules_text = "\n\n".join([doc.page_content for doc in example_docs])

    print("✅ Rules and examples loaded.")
    yield
    print("🛑 Shutting down app.")

# -----------------------------
# Initialize FastAPI with lifespan
# -----------------------------
app = FastAPI(lifespan=lifespan)

# -----------------------------
# Request Schema
# -----------------------------
class ABAPCodeInput(BaseModel):
    code: str

# -----------------------------
# Main Remediation Logic
# -----------------------------
def extract_global_declarations(code: str) -> str:
    lines = code.splitlines()
    global_lines = []

    for line in lines:
        stripped = line.strip().upper()
        if stripped.startswith(("DATA", "DATA:", "TYPES", "TYPES:", "CONSTANTS", "CONSTANTS:")):
            global_lines.append(line)
        elif global_lines and stripped.endswith("."):
            global_lines.append(line)
            break
        elif global_lines:
            global_lines.append(line)

    return "\n".join(global_lines)

def smart_chunk_code(lines, max_lines=600):
    chunks = []
    current_chunk = []
    for line in lines:
        current_chunk.append(line)
        if len(current_chunk) >= max_lines or line.strip().upper().startswith("FORM") or line.strip().upper().startswith("END"):
            chunks.append(current_chunk)
            current_chunk = []
    if current_chunk:
        chunks.append(current_chunk)
    return chunks

def remediate_abap_with_validation(input_code: str, rules_text: str, example_rules_text: str):
    lines = input_code.splitlines()
    # chunk_size = 600
    # chunks = [lines[i:i + chunk_size] for i in range(0, len(lines), chunk_size)]
    chunks = smart_chunk_code(lines, max_lines=500)
    full_output = ""
    global_context = extract_global_declarations(input_code)
    for idx, chunk_lines in enumerate(chunks):
        chunk_code = "\n".join(chunk_lines)
        full_input = f"{global_context}\n\n{chunk_code}"  # Inject global declarations
        prompt = remediate_prompt.format(
            Rules=rules_text,
            example_rules=example_rules_text,
            input_code=full_input
        )
        print(f"🔧 Processing chunk {idx + 1}/{len(chunks)}...")

        try:
            response = llm.invoke(prompt)
            chunk_output = response.content if hasattr(response, "content") else str(response)
            full_output += chunk_output + "\n\n"
        except Exception as e:
            print(f"⚠️ Error processing chunk {idx + 1}: {e}")
            full_output += f"\n* [Chunk {idx + 1} failed: {str(e)}]\n"

    return {"remediated_code": full_output}

# -----------------------------
# FastAPI Endpoint
# -----------------------------
@app.post("/remediate_abap/")
async def remediate_abap(input_data: ABAPCodeInput, request: Request):
    rules_text = request.app.state.rules_text
    example_rules_text = request.app.state.example_rules_text
    return remediate_abap_with_validation(input_data.code, rules_text, example_rules_text)
