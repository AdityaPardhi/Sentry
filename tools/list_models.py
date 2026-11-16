"""List the Gemini models your key can use. Run from the project root:
    python tools/list_models.py"""
import os, sys, json, urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from cli import explain  # loads .env

key = os.environ.get("GEMINI_API_KEY", "").strip()
if not key:
    sys.exit("GEMINI_API_KEY not found in .env")
req = urllib.request.Request("https://generativelanguage.googleapis.com/v1beta/models?pageSize=200",
                             headers={"x-goog-api-key": key})
data = json.loads(urllib.request.urlopen(req, timeout=30).read().decode())
names = sorted(m["name"].split("/")[-1] for m in data.get("models", [])
               if "generateContent" in m.get("supportedGenerationMethods", []) and "flash" in m["name"])
print("Flash models you can use:")
for n in names:
    print("  ", n)