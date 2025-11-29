"""
HAK_GAL v2.2-ALPHA: FastAPI Quickstart Example

Demonstrates how to integrate FirewallEngine into a FastAPI application.

Creator: Joerg Bollwahn
License: MIT
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from hak_gal.core.engine import FirewallEngine
from hak_gal.core.exceptions import SecurityException, BusinessLogicException

app = FastAPI()

# 1. Initialize Engine (Single Instance)
# Note: In production, use dependency injection or singleton pattern
firewall = FirewallEngine()


class ChatRequest(BaseModel):
    """Chat request model."""

    user_id: str
    message: str


class ToolCallRequest(BaseModel):
    """Tool call request model."""

    user_id: str
    tool_name: str
    tool_args: dict


@app.post("/chat")
async def chat_endpoint(req: ChatRequest):
    """
    Chat endpoint with inbound security check.

    Pipeline:
    1. Inbound Check (UnicodeSanitizer -> RegexGate -> SemanticVectorCheck)
    2. LLM Inference (your model here)
    3. Return response
    """
    try:
        # 2. Inbound Check
        await firewall.process_inbound(req.user_id, req.message)

        # ... LLM Inference ...
        # llm_response = model.generate(req.message)
        # tool_call = parse_tool(llm_response)

        # For demo: return success
        return {
            "status": "allowed",
            "processed": True,
            "message": "Request passed security checks",
        }

    except SecurityException as e:
        # Log incident safely (privacy: user_id is already hashed in logs)
        print(f"SECURITY BLOCK: User {req.user_id} (Hashed) - Reason: {str(e)}")
        raise HTTPException(
            status_code=403,
            detail="Request blocked by security policy.",
        )


@app.post("/tool-call")
async def tool_call_endpoint(req: ToolCallRequest):
    """
    Tool call endpoint with outbound security check.

    Pipeline:
    1. Outbound Check (ToolGuardRegistry.validate)
    2. Execute tool (if allowed)
    3. Update context (automatic)
    """
    try:
        # 3. Outbound Check (wenn Tool Call)
        await firewall.process_outbound(req.user_id, req.tool_name, req.tool_args)

        # ... Execute Tool ...
        # result = execute_tool(req.tool_name, req.tool_args)

        # For demo: return success
        return {
            "status": "allowed",
            "tool_executed": True,
            "message": f"Tool '{req.tool_name}' validated and executed",
        }

    except (SecurityException, BusinessLogicException) as e:
        # Log incident safely
        print(f"SECURITY BLOCK: Tool '{req.tool_name}' blocked - Reason: {str(e)}")
        raise HTTPException(
            status_code=403,
            detail=f"Tool call blocked: {str(e)}",
        )


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "2.2-ALPHA",
        "components": {
            "session_manager": "active",
            "vector_check": "active",
            "tool_guard_registry": "active",
        },
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
