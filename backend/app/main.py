import sys
import asyncio
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .schemas import ScanRequest, ScanResult
from .scanner import full_scan

# =======================
# FASTAPI APP (API MODE)
# =======================

app = FastAPI(
    title="Cyber Ultra AI Web Scanner (Advanced)",
    version="1.0.0",
    description="Educational & authorized web security scanner",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {
        "message": "Cyber Ultra Scanner API",
        "mode": "api",
        "docs": "/docs",
    }

@app.post("/api/v1/scan", response_model=ScanResult)
async def scan_url(body: ScanRequest):
    url = body.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    try:
        return await full_scan(url)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}")

# =======================
# CLI MODE (IMPORTANT)
# =======================

def start():
    """
    Entry point for CLI usage
    Example:
        cyber-ultra-scanner example.com
    """

    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  cyber-ultra-scanner <target-url>\n")
        sys.exit(1)

    target = sys.argv[1]
    print(f"\n[+] Cyber Ultra Scanner started")
    print(f"[+] Target: {target}\n")

    try:
        result = asyncio.run(full_scan(target))

        print("========== SCAN RESULT ==========")
        for key, value in result.dict().items():
            print(f"{key}: {value}")

        print("\n[✓] Scan completed successfully")

    except Exception as e:
        print(f"\n[!] Scan failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    start()
