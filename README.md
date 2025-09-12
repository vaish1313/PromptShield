# PromptShield: AI-Powered Prompt Injection Detection

**A real-time security layer for your LLMs. Analyze, detect, and neutralize prompt injection attacks with 91% accuracy, no fine-tuning required.**

---

## Overview

**PromptShield** is a powerful security tool designed to protect AI systems, particularly those built with Large Language Models (LLMs), from a wide range of prompt injection attacks. Leveraging the advanced reasoning capabilities of a powerful backend AI, this application provides a robust defense mechanism by analyzing user inputs in real-time.

As LLMs become more integrated into applications, they are increasingly targeted by malicious inputs designed to hijack their intended function. PromptShield acts as a critical sentinel, identifying and flagging threats such as system instruction overrides, data exfiltration attempts, and sophisticated jailbreaking techniques before they reach your core AI model.

Built with Streamlit, the interactive dashboard allows for immediate analysis, historical review, and insightful analytics, making LLM security accessible and manageable.

## Key Features

- **🛡️ Real-Time Threat Analysis:** Instantly scan and assess user prompts through an intuitive web interface.
- **🧠 Advanced Threat Detection:** Identifies a wide spectrum of attacks:
  - System Prompt Overriding
  - Sensitive Data Exfiltration
  - Jailbreaking & Role-Playing Attacks
  - Delimiter Manipulation
  - Multi-Stage & Obfuscated Attacks (e.g., Unicode)
- **📊 Detailed Security Reports:** For each analysis, receive a clear verdict (Safe/Malicious), a confidence score, and a detailed explanation of the identified threat patterns.
- **📈 Analytics Dashboard:** Visualize security trends with interactive charts tracking total analyses, detection rates, and daily activity.
- **🗂️ Historical Logging:** Automatically stores every analysis in a local SQLite database for audit, review, and further investigation.
- **📥 Exportable Data:** Download the complete analysis history as a CSV file for offline reporting and integration with other security tools.
- **🚀 Lightweight & Self-Contained:** Uses a simple SQLite backend, ensuring easy setup and deployment without heavy dependencies.

## How It Works

PromptShield's effectiveness comes from a sophisticated meta-prompting strategy, where it uses a powerful AI to police other prompts. The process is a multi-step analytical framework:

1.  **Secure Wrapping:** The user's input prompt is securely "wrapped" within a specialized analytical prompt (the "meta-prompt") that contains a carefully engineered set of security instructions and test cases.
2.  **Contextual Analysis:** This combined payload is sent to the backend AI model. The model is instructed not to execute the user's prompt, but to analyze it from a security perspective based on the provided framework.
3.  **Pattern Recognition:** The AI examines the linguistic structure, intent, and hidden commands within the user's prompt to identify malicious patterns.
4.  **Risk Scoring & Reasoning:** Based on its analysis, the model generates a risk assessment, including a confidence score and a natural language explanation for its conclusion.
5.  **Data Persistence:** The user's prompt, along with the detailed analysis results, is logged to the SQLite database for historical tracking.

This approach achieves high accuracy without the need for costly model fine-tuning or extensive datasets, making it an efficient and adaptable security solution.

## Installation

### Prerequisites

- Python 3.8+
- Git

### 1. Clone the Repository

Clone this repository to your local machine:

```
git clone [https://github.com/vaish1313/PromptShield.git](https://github.com/vaish1313/PromptShield.git)
cd prompt-injection-detection

```

### 2. Install Depnedancies

Install all the required Python packages using pip:

```

pip install -r requirements.txt

```

### Configure API Key

Create a file named .env in the root directory of the project and add your API key:

```

GROQ_API_KEY="YOUR_API_KEY_HERE"

```

### Run the Application

Launch the Streamlit application:

```

streamlit run app.py
```

You can now access PromptShield in your web browser, typically at http://localhost:8501.

---

_This project was built to help secure the next generation of AI._
