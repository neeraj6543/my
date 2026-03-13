import os
from dotenv import load_dotenv

# .env file se future me secrets / API keys rakhne ke kaam aayega
load_dotenv()

PROJECT_NAME = "Cyber Ultra AI Web Scanner (Advanced)"
API_V1_PREFIX = "/api/v1"

# Future ke liye placeholder (AI add karoge to kaam aayega)
AI_ENABLED = os.getenv("AI_ENABLED", "false").lower() == "true"
