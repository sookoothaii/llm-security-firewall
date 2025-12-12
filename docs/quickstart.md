# Quickstart Guide - LLM Security Firewall

**Get started in 5 minutes!**

This guide shows you how to integrate the LLM Security Firewall into your application with minimal code.

---

## Installation

```bash
pip install llm-security-firewall
```

That's it! All dependencies are automatically installed.

---

## One-Liner Integration

### Check User Input

```python
from llm_firewall import guard

# Check if user input is safe
result = guard.check_input("Hello, how are you?")
if result.allowed:
    # Send to LLM
    llm_response = call_your_llm(result.sanitized_text or "Hello, how are you?")
else:
    # Block malicious input
    return f"Input blocked: {result.reason}"
```

### Check LLM Output

```python
from llm_firewall import guard

# Generate LLM response (your code)
llm_response = call_your_llm(user_input)

# Validate output before returning
result = guard.check_output(llm_response)
if result.allowed:
    return result.sanitized_text or llm_response
else:
    return "I cannot provide that information."
```

---

## Complete Example

Here's a complete example with both input and output validation:

```python
from llm_firewall import guard

def chat_with_llm(user_input: str) -> str:
    """Chat endpoint with full firewall protection."""

    # Step 1: Validate user input
    input_result = guard.check_input(user_input)
    if not input_result.allowed:
        return f"❌ Input blocked: {input_result.reason}"

    # Step 2: Send to LLM (use sanitized input if available)
    llm_response = call_your_llm(
        input_result.sanitized_text or user_input
    )

    # Step 3: Validate LLM output
    output_result = guard.check_output(llm_response)
    if not output_result.allowed:
        return f"❌ Output blocked: {output_result.reason}"

    # Step 4: Return sanitized output
    return output_result.sanitized_text or llm_response
```

---

## FastAPI Integration

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from llm_firewall import guard

app = FastAPI()

class Message(BaseModel):
    text: str

@app.post("/chat")
async def chat(message: Message):
    # Validate input
    input_result = guard.check_input(message.text)
    if not input_result.allowed:
        raise HTTPException(status_code=400, detail=input_result.reason)

    # Call LLM (replace with your LLM call)
    llm_response = f"Echo: {message.text}"

    # Validate output
    output_result = guard.check_output(llm_response)
    if not output_result.allowed:
        raise HTTPException(status_code=500, detail="Output blocked by firewall")

    return {"response": output_result.sanitized_text or llm_response}
```

---

## What Gets Blocked?

The firewall automatically detects and blocks:

- **Jailbreak Attempts**: Prompt injection, role-playing, DAN attacks
- **Unicode Attacks**: Zero-width characters, RLO/Bidi override
- **Obfuscation**: Concatenation, encoding anomalies
- **Tool Abuse**: Unauthorized tool calls, dangerous arguments
- **Content Violations**: Policy violations, unsafe content

---

## Configuration (Optional)

By default, the firewall works out-of-the-box with sensible defaults. For custom configuration:

```python
from llm_firewall.app.composition_root import CompositionRoot

# Create custom firewall engine
root = CompositionRoot(enable_cache=False)  # Disable Redis cache
engine = root.create_firewall_engine(
    strict_mode=True,  # Block on any threat
    enable_sanitization=True  # Auto-sanitize dangerous content
)

# Use engine directly (advanced)
decision = engine.process_input("user123", "user input")
```

---

## LangChain Integration (Coming Soon)

Protect your LangChain chains with one callback:

```python
from llm_firewall.integrations.langchain import FirewallCallbackHandler

chain = LLMChain(llm=llm, callbacks=[FirewallCallbackHandler()])
```

**Install with LangChain support:**
```bash
pip install llm-security-firewall[langchain]
```

See `examples/langchain_integration.py` for complete example.

## What's Next?

- **Full Documentation**: See `README.md` for complete API reference
- **Examples**: Check `examples/` directory for more integration patterns
- **Architecture**: Read `ARCHITECTURE.md` for design principles
- **Contributing**: See `CONTRIBUTING.md` to contribute

---

## Troubleshooting

### Import Error

If you get `ImportError`, make sure all dependencies are installed:

```bash
pip install --upgrade llm-security-firewall
```

### Redis Connection Error

If you see Redis connection errors, the firewall will gracefully degrade to in-memory mode. This is expected if you don't have Redis running.

To disable Redis entirely:

```python
import os
os.environ["ENABLE_CACHE"] = "false"
```

### Performance

The firewall adds minimal latency:
- **P99 Latency**: <200ms for standard inputs
- **Cache Hit**: <1ms (if Redis available)
- **Single Request Memory**: <50MB

---

## Support

- **GitHub Issues**: [Report bugs or request features](https://github.com/sookoothaii/llm-security-firewall/issues)
- **Documentation**: See `docs/` directory
- **Examples**: See `examples/` directory

---

**Ready to go!** The firewall is now protecting your LLM application. 🛡️
