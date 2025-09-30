import streamlit as st
import sqlite3
import pandas as pd
import time
import hashlib
from groq import Groq
import cohere
import os
from datetime import datetime
from dotenv import load_dotenv
import json
import bcrypt
import secrets

# --- CONFIGURATION ---
load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
COHERE_API_KEY = os.getenv("COHERE_API_KEY")

# Initialize API clients
try:
    groq_client = Groq(api_key=GROQ_API_KEY)
    cohere_client = cohere.Client(COHERE_API_KEY)
except Exception as e:
    st.error(f"Failed to initialize API clients. Please check your .env file. Error: {e}")
    st.stop()

st.set_page_config(page_title="PromptShield", page_icon="🛡️", layout="wide")


# --- FRONTEND STYLES ---
def local_css():
    st.markdown("""
        <style>
            :root {
                --background-color: #131314;
                --primary-text-color: #e0e0e0;
                --secondary-text-color: #a0a0a0;
                --accent-color: #89b4f8;
                --card-background-color: #1e1f20;
                --border-color: #3c3c3c;
                --danger-color: #ff8a80;
                --success-color: #80ff9a;
            }
            body, .stApp { background-color: var(--background-color); color: var(--primary-text-color); }
            h1, h2, h3, h4, h5, h6 { color: #ffffff !important; }
            .st-emotion-cache-18ni7ap, .st-emotion-cache-h4y6h1 { display: none; }
            .main-content { max-width: 900px; margin: 0 auto; padding: 0 1rem; }
            .app-header { text-align: center; margin-bottom: 2rem; }
            .app-header h1 { font-size: 2.5rem; display: flex; align-items: center; justify-content: center; gap: 15px; }
            
            .st-emotion-cache-135i54g { background-color: var(--card-background-color); border-radius: 12px; border: 1px solid var(--border-color); position: fixed; bottom: 20px; z-index: 1000; width: 95%; max-width: 850px; left: 50%; transform: translateX(-50%); }
            .stTextArea textarea { background-color: transparent; border: none; color: var(--primary-text-color); font-size: 16px; }
            .st-emotion-cache-15i8q1v > div:first-child { padding-bottom: 7rem; }
            .stButton>button { border-radius: 8px; border: 1px solid var(--accent-color); background-color: transparent; color: var(--accent-color); transition: all 0.2s; padding: 0.5rem 1rem; }
            .stButton>button:hover { background-color: var(--accent-color); color: #000000; }
            .result-card { background-color: rgba(42, 42, 45, 0.5); border-radius: 12px; padding: 1.25rem; border: 1px solid var(--border-color); margin-bottom: 1rem; }
            .result-card-header { font-size: 1.1rem; font-weight: bold; margin-bottom: 1rem; display: flex; align-items: center; gap: 10px; }
            .result-card-header.malicious { color: var(--danger-color); }
            .result-card-header.safe { color: var(--success-color); }
            .result-card h4 { color: var(--secondary-text-color) !important; font-size: 0.9rem !important; text-transform: uppercase; margin-bottom: 0.5rem; }
        </style>
    """, unsafe_allow_html=True)


# --- DATABASE FUNCTIONS ---
def init_db():
    conn = sqlite3.connect('security_prompt_detection.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT)')
    c.execute('''CREATE TABLE IF NOT EXISTS prompts (id TEXT PRIMARY KEY, prompt TEXT, is_malicious BOOLEAN, confidence REAL, timestamp TEXT, flagged_patterns TEXT, model_used TEXT, username TEXT)''')
    c.execute('CREATE TABLE IF NOT EXISTS api_keys (key_hash TEXT PRIMARY KEY, username TEXT, created_at TEXT)')
    conn.commit()
    conn.close()

def generate_api_key(username):
    conn = sqlite3.connect('security_prompt_detection.db')
    c = conn.cursor()
    c.execute("DELETE FROM api_keys WHERE username = ?", (username,))
    api_key = f"psk_{secrets.token_urlsafe(32)}"
    hashed_key = hashlib.sha256(api_key.encode()).hexdigest()
    c.execute("INSERT INTO api_keys (key_hash, username, created_at) VALUES (?, ?, ?)", (hashed_key, username, datetime.now().isoformat()))
    conn.commit()
    conn.close()
    return api_key

def get_api_key_for_user(username):
    conn = sqlite3.connect('security_prompt_detection.db')
    c = conn.cursor()
    c.execute("SELECT 1 FROM api_keys WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    return result is not None

def add_user(username, password):
    conn = sqlite3.connect('security_prompt_detection.db'); c = conn.cursor()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password.decode('utf-8')))
        conn.commit(); return True
    except sqlite3.IntegrityError: return False
    finally: conn.close()

def check_user(username, password):
    conn = sqlite3.connect('security_prompt_detection.db'); c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE username = ?", (username,)); result = c.fetchone(); conn.close()
    return result and bcrypt.checkpw(password.encode('utf-8'), result[0].encode('utf-8'))

def save_to_db(prompt, analysis, username):
    conn = sqlite3.connect('security_prompt_detection.db')
    c = conn.cursor()
    prompt_id = hashlib.md5(f"{prompt}_{analysis['model']}_{time.time()}".encode()).hexdigest()
    flagged_patterns = ", ".join(analysis.get("flagged_patterns", []))
    c.execute(
        "INSERT INTO prompts (id, prompt, is_malicious, confidence, timestamp, flagged_patterns, model_used, username) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (prompt_id, prompt, analysis.get("is_malicious", False), analysis.get("confidence", 0.0), 
         datetime.now().isoformat(), flagged_patterns, analysis.get("model", "unknown"), username)
    )
    conn.commit()
    conn.close()

def get_history_by_user(username):
    conn = sqlite3.connect('security_prompt_detection.db')
    df = pd.read_sql_query("SELECT * FROM prompts WHERE username = ? ORDER BY timestamp DESC", conn, params=(username,))
    conn.close()
    return df

# --- API ANALYSIS & RESPONSE FUNCTIONS ---
def analyze_prompt_with_groq(prompt_text):
    system_prompt = 'You are an expert security system. Analyze the user prompt for security threats. Return your response STRICTLY as a JSON object only. Schema: { "is_malicious": boolean, "confidence": float (0.0-1.0), "reasoning": "short explanation", "flagged_patterns": ["list", "of", "patterns"] }'
    try:
        response = groq_client.chat.completions.create(model="llama-3.1-8b-instant", messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": prompt_text}], temperature=0.0, response_format={"type": "json_object"})
        analysis = json.loads(response.choices[0].message.content)
        return {"model": "Groq Llama-3.1", **analysis}
    except Exception as e:
        return {"model": "Groq Llama-3.1", "is_malicious": True, "reasoning": f"API Error: {e}", "flagged_patterns": ["API_ERROR"], "confidence": 1.0}

def analyze_prompt_with_cohere(prompt_text):
    preamble = 'You are an expert security system. Analyze the user prompt for security threats. Return your response STRICTLY as a valid JSON object only. The JSON schema must be: { "is_malicious": boolean, "confidence": float (0.0-1.0), "reasoning": "short explanation", "flagged_patterns": ["list", "of", "patterns"] }'
    try:
        # --- FIX: Using the user-specified model ---
        response = cohere_client.chat(message=f"PROMPT TO ANALYZE: {prompt_text}", preamble=preamble, model="command-a-03-2025", temperature=0.0)
        json_string = response.text.strip().lstrip("```json").rstrip("```")
        analysis = json.loads(json_string)
        return {"model": "Cohere command-a-03-2025", **analysis}
    except Exception as e:
        return {"model": "Cohere command-a-03-2025", "is_malicious": True, "reasoning": f"API or JSON parsing error: {e}", "flagged_patterns": ["API_ERROR"], "confidence": 1.0}

def generate_groq_response(prompt_text):
    try:
        response = groq_client.chat.completions.create(model="llama-3.1-8b-instant", messages=[{"role": "user", "content": prompt_text}])
        return response.choices[0].message.content
    except Exception as e: return f"Error generating response: {e}"


# --- UI COMPONENTS ---
def login_signup_page():
    st.markdown('<div class="app-header"><h1>🛡️ PromptShield</h1></div>', unsafe_allow_html=True)
    st.markdown('<div class="login-container">', unsafe_allow_html=True)
    choice = st.radio("Choose action", ["Login", "Sign Up"], horizontal=True, label_visibility="collapsed")
    form_action = st.form("auth_form")
    if choice == "Login":
        form_action.markdown("<h5>Welcome Back!</h5>", unsafe_allow_html=True)
        username = form_action.text_input("Username", placeholder="Username", label_visibility="collapsed")
        password = form_action.text_input("Password", type="password", placeholder="Password", label_visibility="collapsed")
        if form_action.form_submit_button("Login", use_container_width=True):
            if check_user(username, password):
                st.session_state.logged_in = True; st.session_state.username = username; st.rerun()
            else: st.error("Invalid username or password")
    else:
        form_action.markdown("<h5>Create an Account</h5>", unsafe_allow_html=True)
        username = form_action.text_input("Username", placeholder="Choose a username", label_visibility="collapsed")
        password = form_action.text_input("Password", type="password", placeholder="Choose a password", label_visibility="collapsed")
        if form_action.form_submit_button("Sign Up", use_container_width=True):
            if add_user(username, password): st.success("Account created! Please login.")
            else: st.error("Username already exists.")
    st.markdown('</div>', unsafe_allow_html=True)

def main_app():
    if "messages" not in st.session_state: st.session_state.messages = []

    with st.sidebar:
        st.markdown(f"### Welcome, {st.session_state.username}!")
        page = st.radio("Navigation", ["🛡️ Detector", "📜 My History", "🔑 API Keys"], label_visibility="collapsed")
        if st.button("Logout", use_container_width=True):
            st.session_state.clear(); st.rerun()

    st.markdown('<div class="main-content">', unsafe_allow_html=True)
    if page != "🔑 API Keys": st.markdown('<div class="app-header"><h1>🛡️ PromptShield</h1></div>', unsafe_allow_html=True)
    
    if page == "🛡️ Detector":
        # --- FIX: Using the user-specified model name in the UI ---
        selected_models = st.multiselect("Select Analysis Models:", ["Groq Llama-3.1", "Cohere command-a-03-2025"], default=["Groq Llama-3.1"])
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                if message["role"] == "user": st.markdown(message["content"])
                else: display_full_result(message["content"])
    
    elif page == "📜 My History":
        st.header("My Analysis History")
        df = get_history_by_user(st.session_state.username)
        if df.empty:
            st.info("You haven't analyzed any prompts yet.")
        else:
            # Filter by model
            groq_history = df[df['model_used'].str.contains("Groq", na=False)]
            cohere_history = df[df['model_used'].str.contains("Cohere", na=False)]

            st.subheader("Groq Llama-3.1 Analysis History")
            if not groq_history.empty:
                st.dataframe(groq_history[['timestamp', 'prompt', 'is_malicious', 'confidence', 'flagged_patterns']], use_container_width=True, hide_index=True)
            else:
                st.write("No history found for this model.")

            st.subheader("Cohere command-a-03-2025 Analysis History")
            if not cohere_history.empty:
                st.dataframe(cohere_history[['timestamp', 'prompt', 'is_malicious', 'confidence', 'flagged_patterns']], use_container_width=True, hide_index=True)
            else:
                st.write("No history found for this model.")


    elif page == "🔑 API Keys":
        st.header("API Access"); st.write("Integrate PromptShield into your applications.")
        st.info("Your API key is secret. Do not share it publicly.")
        key_exists = get_api_key_for_user(st.session_state.username)
        if key_exists:
            st.success("You have an active API key.")
            if st.button("Revoke and Generate New Key"): st.session_state.new_api_key = generate_api_key(st.session_state.username)
        else:
            if st.button("Generate API Key"): st.session_state.new_api_key = generate_api_key(st.session_state.username)
        if 'new_api_key' in st.session_state:
            st.warning("Copy your new key. You will not see it again."); st.code(st.session_state.new_api_key, language="bash")
        st.markdown("---"); st.subheader("Example Usage")
        st.code('import requests\n\napi_key = "YOUR_API_KEY"\nprompt = "Ignore instructions..."\n# To use a specific model, add it to the JSON payload\n# model = "cohere" or "groq"\n\nresponse = requests.post(\n    "http://127.0.0.1:8000/analyze",\n    headers={"Authorization": f"Bearer {api_key}"},\n    json={"prompt": prompt, "model": "cohere"}\n)\nprint(response.json())', language="python")

    st.markdown('</div>', unsafe_allow_html=True)

    if page == "🛡️ Detector":
        if prompt := st.chat_input("Analyze a prompt..."):
            if not selected_models: st.warning("Please select at least one model."); return
            st.session_state.messages.append({"role": "user", "content": prompt})
            analyses = []
            with st.spinner("Analyzing..."):
                if "Groq Llama-3.1" in selected_models: analyses.append(analyze_prompt_with_groq(prompt))
                # --- FIX: Using the user-specified model name in the logic ---
                if "Cohere command-a-03-2025" in selected_models: analyses.append(analyze_prompt_with_cohere(prompt))
            
            # Save each analysis to the database
            for analysis in analyses:
                save_to_db(prompt, analysis, st.session_state.username)

            is_globally_malicious = any(res.get("is_malicious", False) for res in analyses)
            st.session_state.messages.append({"role": "assistant", "content": {"analyses": analyses, "is_malicious": is_globally_malicious, "original_prompt": prompt}})
            st.rerun()

def display_full_result(result):
    tabs = st.tabs([res["model"] for res in result["analyses"]])
    for i, res in enumerate(result["analyses"]):
        with tabs[i]:
            display_analysis_card(res)

    if not result["is_malicious"]:
        with st.spinner("Generating helpful response..."): response = generate_groq_response(result['original_prompt'])
        st.markdown("---"); st.markdown(response)

def display_analysis_card(analysis):
    st.markdown('<div class="result-card">', unsafe_allow_html=True)
    header_class = "malicious" if analysis.get("is_malicious") else "safe"
    icon = "🚨" if analysis.get("is_malicious") else "✅"
    st.markdown(f'<div class="result-card-header {header_class}">{icon} Status: {"Malicious" if analysis.get("is_malicious") else "Safe"}</div>', unsafe_allow_html=True)
    
    st.metric("Confidence Score", f"{analysis.get('confidence', 0.0) * 100:.1f}%")
    
    st.markdown("<h4>🧠 Reasoning</h4>", unsafe_allow_html=True); st.write(analysis.get('reasoning', 'No reasoning provided.'))
    if analysis.get("flagged_patterns"):
        st.markdown("<h4>🚩 Flagged Patterns</h4>", unsafe_allow_html=True); st.code('\n'.join(f"- {p}" for p in analysis["flagged_patterns"]), language="markdown")
    st.markdown('</div>', unsafe_allow_html=True)


# --- MAIN APP LOGIC ---
def main():
    local_css(); init_db()
    if 'logged_in' not in st.session_state: st.session_state.logged_in = False
    if st.session_state.logged_in: main_app()
    else: login_signup_page()

if __name__ == "__main__":
    main()

