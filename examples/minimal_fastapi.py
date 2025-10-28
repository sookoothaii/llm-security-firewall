"""
Minimal FastAPI Integration Example for LLM Security Firewall

This example demonstrates how to integrate the firewall as middleware
in a FastAPI application with in-memory configuration (no PostgreSQL required).

Requirements:
    pip install fastapi uvicorn llm-security-firewall

Usage:
    python examples/minimal_fastapi.py
    
    Then test with:
    curl -X POST http://localhost:8000/chat -H "Content-Type: application/json" -d '{"message": "Hello!"}'
"""

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import sys
from pathlib import Path

# Add parent directory to path for local development
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from llm_firewall.core import SecurityFirewall, FirewallConfig

# Initialize FastAPI app
app = FastAPI(
    title="LLM Security Firewall Demo",
    description="Minimal example of firewall integration",
    version="1.0.0"
)

# Load minimal configuration (in-memory mode, no DB required)
config = FirewallConfig.from_yaml("config/config.minimal.yaml")
firewall = SecurityFirewall(config)


class ChatMessage(BaseModel):
    """Chat message schema"""
    message: str


class ChatResponse(BaseModel):
    """Chat response schema"""
    response: str
    firewall_decision: str
    confidence: float


@app.middleware("http")
async def firewall_input_middleware(request: Request, call_next):
    """
    Middleware to validate input before processing.
    
    Checks all POST/PUT requests for malicious content.
    """
    if request.method in ["POST", "PUT"]:
        # Read request body
        body = await request.body()
        
        try:
            # Validate input through firewall
            is_safe, reason = firewall.validate_input(body.decode("utf-8"))
            
            if not is_safe:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "Input blocked by firewall",
                        "reason": reason,
                        "blocked_by": "input_firewall"
                    }
                )
        except Exception as e:
            # Fail-closed: reject on error
            return JSONResponse(
                status_code=500,
                content={
                    "error": "Firewall error",
                    "message": str(e)
                }
            )
    
    # Continue processing
    response = await call_next(request)
    return response


@app.post("/chat", response_model=ChatResponse)
async def chat_endpoint(message: ChatMessage):
    """
    Simple chat endpoint with output validation.
    
    Args:
        message: User message
        
    Returns:
        ChatResponse with firewall decision
    """
    # Simulate LLM response (in real app, call your LLM here)
    llm_response = f"Echo: {message.message}"
    
    # Validate output through firewall
    decision = firewall.validate_evidence(
        content=llm_response,
        sources=[],  # No external sources in this simple example
        kb_facts=[]  # No KB facts in this simple example
    )
    
    # Map decision to string
    if decision.should_promote:
        decision_str = "PROMOTE"
    elif decision.should_quarantine:
        decision_str = "QUARANTINE"
    else:
        decision_str = "REJECT"
    
    # Return response with firewall metadata
    return ChatResponse(
        response=llm_response,
        firewall_decision=decision_str,
        confidence=decision.confidence
    )


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    # Run firewall health checks
    has_drift, scores = firewall.check_drift(sample_size=5)
    alerts = firewall.get_alerts(domain="SCIENCE")
    
    return {
        "status": "healthy",
        "firewall": {
            "memory_drift": has_drift,
            "canary_scores": scores,
            "active_alerts": len(alerts)
        }
    }


@app.get("/")
async def root():
    """Root endpoint with usage instructions"""
    return {
        "service": "LLM Security Firewall Demo",
        "version": "1.0.0",
        "endpoints": {
            "POST /chat": "Send chat message (input + output validation)",
            "GET /health": "Health check with firewall status",
            "GET /docs": "OpenAPI documentation"
        },
        "example_request": {
            "url": "http://localhost:8000/chat",
            "method": "POST",
            "body": {
                "message": "Hello, how are you?"
            }
        }
    }


if __name__ == "__main__":
    import uvicorn
    
    print("Starting LLM Security Firewall Demo...")
    print("API Documentation: http://localhost:8000/docs")
    print("Health Check: http://localhost:8000/health")
    print("\nExample request:")
    print('  curl -X POST http://localhost:8000/chat -H "Content-Type: application/json" -d \'{"message": "Hello!"}\'')
    
    uvicorn.run(app, host="0.0.0.0", port=8000)

