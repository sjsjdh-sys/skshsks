import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from tool_api.config import settings
from tool_api.routers import health, nodes , tool



app = FastAPI(
    title="TOOL API",
    description="REST interface for the TOOL graph backend.",
    version="0.1.0",
)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Front End dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(health.router)
app.include_router(nodes.router, prefix="/api/v1")
app.include_router(tool.router, prefix="/api/v1")


@app.get("/", tags=["root"])
def root() -> dict[str, str]:
    return {"message": "TOOL API", "docs": "/docs"}


# ── Entrypoint ────────────────────────────────────────────────────────────────
def start() -> None:
    """CLI entrypoint used by the `start-api` script."""
    uvicorn.run(
        "tool_api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.api_reload,
    )


if __name__ == "__main__":
    start()
