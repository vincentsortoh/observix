from fastapi import FastAPI, HTTPException
import httpx
from typing import Dict, Any

import os
import asyncio
import json
from loguru import logger
from bootstrap import bootstrap, setup_all_tracing, quickstart, bootstrap_with_log_export_only

#print("=== Testing Enhanced Bootstrap Functionality ===")

# Option 1: Use enhanced setup_all_tracing with integrated log export
#print("\n1. Using enhanced setup_all_tracing...")
result = setup_all_tracing(
    config_path="config.json",
    enable_loguru=True,
    loguru_bridge_to_std=True,
    enable_log_export=True
)

app = FastAPI(title="JSONPlaceholder API Service")

@app.get("/users/{user_id}")
async def get_user(user_id: int) -> Dict[str, Any]:
    """
    Get user information from JSONPlaceholder API
    """
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"https://jsonplaceholder.typicode.com/users/{user_id}")
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                raise HTTPException(status_code=404, detail="User not found")
            raise HTTPException(status_code=e.response.status_code, detail="Error fetching user data")
        except httpx.RequestError:
            raise HTTPException(status_code=500, detail="Failed to connect to external API")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8100)