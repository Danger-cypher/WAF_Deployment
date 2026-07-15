import os
import uvicorn

if __name__ == "__main__":
    env_mode = os.getenv("WAF_ENV", "production").lower()
    reload_mode = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes") or env_mode == "development"

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=reload_mode
    )

