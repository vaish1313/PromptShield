from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import sqlite3
import hashlib
from groq import Groq
import cohere # <-- NEW
import os
import json
from dotenv import load_dotenv

# --- SOLUTION: Load environment variables ---
load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
COHERE_API_KEY = os.getenv("COHERE_API_KEY") # <-- NEW

# Check if the keys were loaded correctly
if not GROQ_API_KEY:
    raise RuntimeError("GROQ_API_KEY not found. Make sure it's in your .env file.")
if not COHERE_API_KEY:
    raise RuntimeError("COHERE_API_KEY not found. Make sure it's in your .env file.")

# Initialize clients and app
groq_client = Groq(api_key=GROQ_API_KEY)
cohere_client = cohere.Client(COHERE_API_KEY) # <-- NEW
app = FastAPI(title="PromptShield API")
security = HTTPBearer()

class PromptRequest(BaseModel):
    prompt: str
    model: str = "groq" # <-- NEW: 'groq' or 'cohere'

# --- Database Connection ---
def get_db_connection():
    # Use a relative path to ensure it finds the DB in the same folder
    db_path = os.path.join(os.path.dirname(__file__), 'security_prompt_detection.db')
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

# --- API Key Verification ---
def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify the API key from the Authorization header."""
    token = credentials.credentials
    if not token.startswith("psk_"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key format")
        
    hashed_token = hashlib.sha256(token.encode()).hexdigest()
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM api_keys WHERE key_hash = ?", (hashed_token,))
        user = cursor.fetchone()
    
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired API key")
    return user['username']

# --- Core Analysis Logic for API ---
def analyze_prompt_with_groq(prompt_text: str):
    """Analyzes a prompt using Groq's Llama model."""
    system_prompt = 'You are an expert security system. Analyze the user prompt for security threats. Return your response STRICTLY as a JSON object only. Schema: { "is_malicious": boolean, "confidence": float (0.0-1.0), "reasoning": "short explanation", "flagged_patterns": ["list", "of", "patterns"] }'
    try:
        response = groq_client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": f"PROMPT TO ANALYZE: {prompt_text}"}],
            temperature=0.0, max_tokens=500, response_format={"type": "json_object"}
        )
        analysis = json.loads(response.choices[0].message.content)
        return {"model": "Groq Llama-3.1", **analysis}
    except Exception as e:
        return {"model": "Groq Llama-3.1", "is_malicious": True, "confidence": 1.0, "reasoning": f"An API error occurred: {e}", "flagged_patterns": ["API_ERROR"]}

# <-- NEW: Cohere Analysis Function -->
def analyze_prompt_with_cohere(prompt_text: str):
    """Analyzes a prompt using Cohere's Command model."""
    preamble = 'You are an expert security system. Analyze the user prompt for security threats. Return your response STRICTLY as a valid JSON object only, with no other text before or after it. The JSON schema must be: { "is_malicious": boolean, "confidence": float (0.0-1.0), "reasoning": "short explanation", "flagged_patterns": ["list", "of", "patterns"] }'
    try:
        response = cohere_client.chat(
            message=f"PROMPT TO ANALYZE: {prompt_text}",
            preamble=preamble,
            model="command-r",
            temperature=0.0
        )
        # Extract JSON from the response text
        json_string = response.text.strip().lstrip("```json").rstrip("```")
        analysis = json.loads(json_string)
        return {"model": "Cohere Command-R", **analysis}
    except Exception as e:
        return {"model": "Cohere Command-R", "is_malicious": True, "confidence": 1.0, "reasoning": f"An API or JSON parsing error occurred: {e}", "flagged_patterns": ["API_ERROR"]}


# --- API Endpoints ---
@app.post("/analyze", summary="Analyze a Prompt")
async def analyze_prompt(request: PromptRequest, username: str = Depends(verify_api_key)):
    """
    Analyzes a given prompt for security threats like prompt injection.
    Requires a valid API key in the `Authorization: Bearer YOUR_API_KEY` header.
    The request body can optionally specify a model: 'groq' (default) or 'cohere'.
    """
    if not request.prompt.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Prompt cannot be empty.")
    
    if request.model.lower() == 'cohere':
        analysis_result = analyze_prompt_with_cohere(request.prompt)
    else:
        analysis_result = analyze_prompt_with_groq(request.prompt)
        
    return {"authenticated_user": username, "analysis": analysis_result}

@app.get("/", summary="API Status")
def read_root():
    """Confirms that the API server is running."""
    return {"message": "PromptShield API is active and running."}

