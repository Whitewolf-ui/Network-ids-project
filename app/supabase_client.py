import os
from dotenv import load_dotenv
from supabase import create_client

# Load environment variables from .env file (project root)
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

if not SUPABASE_URL:
    raise RuntimeError("SUPABASE_URL is not set. Check your .env file.")

if not SUPABASE_SERVICE_ROLE_KEY:
    raise RuntimeError("SUPABASE_SERVICE_ROLE_KEY is not set. Check your .env file.")

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)