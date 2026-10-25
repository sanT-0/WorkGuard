import uvicorn
import os, sys

sys.path.insert(0, os.path.dirname(__file__))

if __name__ == "__main__":
    print("Starting WorkGuard Control API on http://127.0.0.1:8000 ...")
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=False)
