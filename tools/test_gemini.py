"""Check that the Gemini key in .env works. Run from the project root:
    python tools/test_gemini.py        (put this file in tools/)
Works in PowerShell or WSL. Never prints the key."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from cli import explain  # loads .env automatically

key = os.environ.get("GEMINI_API_KEY", "").strip()
if not key:
    sys.exit("FAIL: GEMINI_API_KEY not found. Check .env in the project root (line: GEMINI_API_KEY=yourkey).")
print(f"Key found ({len(key)} characters). Calling model...")
try:
    print("Gemini replied:", explain._call_api("Reply with the word OK", key).strip()[:200])
    print("PASS: the AI explanation will work.")
except Exception as e:
    print("FAIL:", type(e).__name__, e)
    print("401/403 = bad or restricted key; 429 = quota; 404 = model name; timeout/connection = no internet.")

    