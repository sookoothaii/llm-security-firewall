"""
Proxy Server with NVIDIA NeMo-inspired Features

Integrates TopicFence, SafetyTemplates, and SafetyFallbackJudge
into a unified HTTP proxy for LLM requests.

Creator: Joerg Bollwahn
Date: 2025-01-XX
License: MIT
"""

import sys
import logging
import time
import uuid
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

# HTTP client for Ollama
try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False
    logging.warning("httpx not installed. Install with: pip install httpx")

# Add paths
project_root = Path(__file__).parent.parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

# Import NeMo features
from llm_firewall.input_protection.topic_fence import TopicFence

# Import RC10b components
from llm_firewall.agents.detector import AgenticCampaignDetector, CampaignResult
from llm_firewall.agents.config import RC10bConfig
from llm_firewall.agents.inspector import ArgumentInspector
from llm_firewall.agents.memory import HierarchicalMemory
from llm_firewall.detectors.tool_killchain import ToolEvent

# Import kids_policy modules (with graceful fallback for TF issues)
kids_policy_path = project_root / "kids_policy"
sys.path.insert(0, str(kids_policy_path.parent))

# Try to import response_templates and fallback_judge (these don't require TF)
try:
    # Import directly from files to avoid __init__.py which loads TruthPreservationValidator
    import importlib.util
    
    # Load response_templates.py directly
    response_templates_path = kids_policy_path / "response_templates.py"
    if response_templates_path.exists():
        spec = importlib.util.spec_from_file_location("response_templates", response_templates_path)
        if spec and spec.loader:
            response_templates_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(response_templates_module)
            SafetyTemplates = response_templates_module.SafetyTemplates
        else:
            raise ImportError("Could not load response_templates")
    else:
        raise ImportError("response_templates.py not found")
    
    # Load fallback_judge.py directly
    fallback_judge_path = kids_policy_path / "fallback_judge.py"
    if fallback_judge_path.exists():
        spec = importlib.util.spec_from_file_location("fallback_judge", fallback_judge_path)
        if spec and spec.loader:
            fallback_judge_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(fallback_judge_module)
            SafetyFallbackJudge = fallback_judge_module.SafetyFallbackJudge
        else:
            raise ImportError("Could not load fallback_judge")
    else:
        raise ImportError("fallback_judge.py not found")
    
except (ImportError, Exception) as e:
    logging.warning(f"Could not import kids_policy modules: {e}. Using fallback stubs.")
    # Fallback: create minimal stubs
    class SafetyTemplates:
        @classmethod
        def get_template(cls, violation_type: str, language: str = "de") -> str:
            templates = {
                "OFF_TOPIC": "Ich bin dein Mathe-Tutor. Lass uns bitte bei Schulthemen bleiben.",
                "UNSAFE_CONTENT": "Dieses Thema ist für unser Alter nicht geeignet.",
                "TRUTH_VIOLATION": "Das stimmt so nicht ganz. Wissenschaftlich gesehen...",
                "GENERIC_BLOCK": "Ich kann dir bei dieser Frage nicht helfen."
            }
            return templates.get(violation_type, f"[Template for {violation_type}]")
    
    class SafetyFallbackJudge:
        def evaluate_safety(self, input_text: str, age_band: str) -> bool:
            # Simple keyword-based check
            unsafe_keywords = ["bombe", "waffe", "töten", "mord", "selbstmord", "sex", "porno"]
            text_lower = input_text.lower()
            return not any(keyword in text_lower for keyword in unsafe_keywords)

# TruthPreservationValidator (may fail due to TF issues - that's OK)
HAS_TRUTH_VALIDATOR = False
TruthPreservationValidatorV2_3 = None
ValidationResult = None

# Global session store for RC10b (in-memory)
# Key: session_id, Value: HierarchicalMemory
SESSION_STORE: Dict[str, HierarchicalMemory] = {}

# Maximum number of events to keep in history (sliding window)
MAX_HISTORY_EVENTS = 50

# Request logging for admin dashboard (rolling buffer, max 100 entries)
REQUEST_LOGS: List[Dict[str, Any]] = []
MAX_REQUEST_LOGS = 100

# Server start time for uptime calculation
SERVER_START_TIME = time.time()

try:
    from fastapi import FastAPI, Request, HTTPException
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    logging.warning("FastAPI not installed. Install with: pip install fastapi uvicorn")

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


@dataclass
class ProxyConfig:
    """Configuration for the proxy server."""
    port: int = 8081
    allowed_topics: list[str] = None
    age_band: str = "9-12"
    topic_threshold: float = 0.3
    enable_fallback_judge: bool = True
    
    # Ollama configuration
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1"
    ollama_timeout: float = 30.0
    enable_ollama: bool = True
    
    def __post_init__(self):
        if self.allowed_topics is None:
            self.allowed_topics = ["Mathe", "Physik", "Chemie", "Biologie"]


class ProxyRequest(BaseModel):
    """Request model for proxy endpoint."""
    message: str
    age_band: Optional[str] = None
    allowed_topics: Optional[list[str]] = None
    session_id: Optional[str] = None
    topic_id: Optional[str] = None  # For Kids Policy Truth Preservation


class ProxyResponse(BaseModel):
    """Response model for proxy endpoint."""
    status: str  # "ALLOWED", "BLOCKED_OFF_TOPIC", "BLOCKED_UNSAFE", "BLOCKED_CAMPAIGN", "BLOCKED_TRUTH_VIOLATION"
    response: str
    metadata: Dict[str, Any]
    llm_output: Optional[str] = None  # LLM response (if allowed and generated)


class LLMProxyServer:
    """
    HTTP Proxy Server with NeMo-inspired safety layers.
    
    Flow:
    1. Layer 1 (Fast Check): TopicFence.is_on_topic()
    2. Layer 2 (Deep Check): Placeholder for RC10b/KidsValidator
    3. Layer 3 (Fallback): SafetyFallbackJudge if no YAML exists
    """
    
    def __init__(self, config: Optional[ProxyConfig] = None):
        """Initialize the proxy server."""
        self.config = config or ProxyConfig()
        
        # Initialize NeMo components
        self.topic_fence = TopicFence()
        self.fallback_judge = SafetyFallbackJudge(llm_provider=None)  # Mock mode
        
        # Initialize RC10b detector
        rc10b_config = RC10bConfig(
            use_policy_layer=True,
            use_scope_mismatch=True,
            use_high_watermark=True,
            use_phase_floor=True
        )
        self.agent_detector = AgenticCampaignDetector(config=rc10b_config)
        
        # Initialize Argument Inspector (RC10c - DLP Lite)
        self.argument_inspector = ArgumentInspector()
        
        # Initialize Kids Policy Truth Preservation Validator (if available)
        self.truth_validator = None
        if HAS_TRUTH_VALIDATOR:
            try:
                self.truth_validator = TruthPreservationValidatorV2_3()
                logger.info("TruthPreservationValidator initialized")
            except Exception as e:
                logger.warning(f"Could not initialize TruthPreservationValidator: {e}")
        
        # Initialize HTTP client for Ollama
        self.ollama_client = None
        if self.config.enable_ollama and HAS_HTTPX:
            try:
                self.ollama_client = httpx.Client(
                    base_url=self.config.ollama_url,
                    timeout=self.config.ollama_timeout
                )
                # Test connection
                try:
                    response = self.ollama_client.get("/api/tags")
                    if response.status_code == 200:
                        logger.info(f"Ollama connected: {self.config.ollama_url} (model: {self.config.ollama_model})")
                    else:
                        logger.warning(f"Ollama connection test failed: {response.status_code}")
                        self.ollama_client = None
                except Exception as e:
                    logger.warning(f"Ollama not available: {e}. Falling back to mock mode.")
                    self.ollama_client = None
            except Exception as e:
                logger.warning(f"Could not initialize Ollama client: {e}")
        
        logger.info("=" * 70)
        logger.info("🛡️  Guardian Firewall Proxy Server")
        logger.info("=" * 70)
        logger.info(f"📍 Port: {self.config.port}")
        logger.info(f"📚 Allowed topics: {self.config.allowed_topics}")
        logger.info(f"🔒 RC10b detector: ✅ enabled")
        logger.info(f"👶 Kids Policy Truth Validator: {'✅ enabled' if self.truth_validator else '⚠️  disabled'}")
        logger.info(f"🤖 Ollama integration: {'✅ enabled' if self.ollama_client else '⚠️  disabled (mock mode)'}")
        if self.ollama_client:
            logger.info(f"   └─ Model: {self.config.ollama_model} @ {self.config.ollama_url}")
        logger.info("=" * 70)
        logger.info("🚀 Server ready! Waiting for requests...")
        logger.info("=" * 70)
    
    def _get_or_create_session_id(self, session_id: Optional[str] = None) -> str:
        """Get or create a session ID."""
        if session_id:
            return session_id
        return str(uuid.uuid4())
    
    def _get_or_create_memory(self, session_id: str) -> HierarchicalMemory:
        """Get or create hierarchical memory for a session."""
        if session_id not in SESSION_STORE:
            SESSION_STORE[session_id] = HierarchicalMemory(session_id=session_id)
        return SESSION_STORE[session_id]
    
    def _get_session_history(self, session_id: str) -> List[ToolEvent]:
        """Get event history for a session (from tactical buffer)."""
        memory = SESSION_STORE.get(session_id)
        if memory is None:
            return []
        return memory.get_history()
    
    def _get_max_reached_phase(self, session_id: str) -> int:
        """Get the maximum kill-chain phase ever reached for a session."""
        memory = SESSION_STORE.get(session_id)
        if memory is None:
            return 0
        return memory.max_phase_ever
    
    def _add_event_to_session(self, session_id: str, event: ToolEvent):
        """
        Add an event to session memory.
        
        Uses HierarchicalMemory which handles:
        - Tactical buffer (sliding window of 50 events)
        - Strategic profile (latent risk, max phase)
        """
        memory = self._get_or_create_memory(session_id)
        memory.add_event(event)
    
    def _call_ollama(self, user_input: str) -> str:
        """
        Call Ollama LLM API.
        
        Args:
            user_input: User's input message
        
        Returns:
            LLM response text
        
        Raises:
            Exception if Ollama call fails
        """
        if not self.ollama_client:
            raise RuntimeError("Ollama client not initialized")
        
        # Ollama API: POST /api/generate
        # Alternative: /api/chat (for chat format)
        payload = {
            "model": self.config.ollama_model,
            "prompt": user_input,
            "stream": False  # Non-streaming for simplicity
        }
        
        try:
            logger.debug(f"Calling Ollama API: POST /api/generate with model {self.config.ollama_model}")
            response = self.ollama_client.post("/api/generate", json=payload, timeout=30.0)
            response.raise_for_status()
            result = response.json()
            
            # Ollama returns {"response": "..."}
            llm_response = result.get("response", "").strip()
            if not llm_response:
                logger.warning("Ollama returned empty response")
                raise ValueError("Empty response from Ollama")
            
            logger.info(f"Ollama response received ({len(llm_response)} chars)")
            return llm_response
        except httpx.TimeoutException as e:
            logger.error(f"Ollama timeout: {e}")
            raise
        except httpx.HTTPStatusError as e:
            logger.error(f"Ollama HTTP error {e.response.status_code}: {e.response.text}")
            raise
        except httpx.HTTPError as e:
            logger.error(f"Ollama HTTP error: {e}")
            raise
        except KeyError as e:
            logger.error(f"Ollama response missing key: {e}. Full response: {result}")
            raise
        except Exception as e:
            logger.error(f"Ollama call error: {e}", exc_info=True)
            raise
    
    def _generate_llm_response(self, user_input: str) -> str:
        """
        Generate LLM response (Ollama or mock fallback).
        
        Args:
            user_input: User's input message
        
        Returns:
            LLM response text
        """
        if self.ollama_client:
            try:
                return self._call_ollama(user_input)
            except Exception as e:
                logger.warning(f"Ollama call failed: {e}. Falling back to mock.")
                # Fall through to mock
        
        # Fallback: Mock response
        return f"[Mock Response] Echo: {user_input}"
    
    def process_request(
        self,
        user_input: str,
        age_band: Optional[str] = None,
        allowed_topics: Optional[list[str]] = None,
        session_id: Optional[str] = None,
        topic_id: Optional[str] = None
    ) -> ProxyResponse:
        """
        Process a user request through the safety pipeline.
        
        Args:
            user_input: The user's input message
            age_band: Age range (e.g., "6-8", "9-12", "13-15")
            allowed_topics: List of allowed topics (overrides config)
            session_id: Session identifier (for RC10b history tracking)
            topic_id: Topic identifier (for Kids Policy Truth Preservation)
        
        Returns:
            ProxyResponse with status, response text, and metadata
        """
        age_band = age_band or self.config.age_band
        allowed_topics = allowed_topics or self.config.allowed_topics
        session_id = self._get_or_create_session_id(session_id)
        
        metadata = {
            "age_band": age_band,
            "allowed_topics": allowed_topics,
            "session_id": session_id,
            "layers_checked": []
        }
        
        # Layer 0: Safety-First Check (UNSAFE_CONTENT before topic check)
        # This ensures dangerous content is blocked even if it's "on topic"
        logger.info(f"[Layer 0] Safety-First check: {user_input[:50]}...")
        try:
            is_safe_input = self.fallback_judge.evaluate_safety(user_input, age_band)
            metadata["kids_input_safe"] = is_safe_input
            metadata["layers_checked"].append("safety_first")
            
            if not is_safe_input:
                logger.warning(f"[Layer 0] UNSAFE_CONTENT detected for age_band {age_band}")
                return ProxyResponse(
                    status="BLOCKED_UNSAFE",
                    response=SafetyTemplates.get_template("UNSAFE_CONTENT", "de"),
                    metadata=metadata
                )
        except Exception as e:
            logger.warning(f"[Layer 0] Safety-First check error: {e}")
            # Continue if check fails (fail-open for safety)
        
        logger.info("[Layer 0] SAFE - proceeding to Layer 1")
        
        # Layer 1: Topic Fence (Fast Check)
        logger.info(f"[Layer 1] Topic Fence check: {user_input[:50]}...")
        is_on_topic = self.topic_fence.is_on_topic(
            user_input,
            allowed_topics,
            threshold=self.config.topic_threshold
        )
        metadata["layers_checked"].append("topic_fence")
        
        if not is_on_topic:
            best_topic, score = self.topic_fence.get_best_topic(user_input, allowed_topics)
            metadata["best_topic_match"] = best_topic
            metadata["similarity_score"] = score
            
            logger.warning(f"[Layer 1] OFF_TOPIC detected: {best_topic} (score: {score:.3f})")
            
            return ProxyResponse(
                status="BLOCKED_OFF_TOPIC",
                response=SafetyTemplates.get_template("OFF_TOPIC", "de"),
                metadata=metadata
            )
        
        logger.info("[Layer 1] ON_TOPIC - proceeding to Layer 2")
        
        # Layer 2A: RC10b Campaign Detection + Argument Inspection (RC10c)
        logger.info(f"[Layer 2A] RC10b Campaign Detection for session {session_id}")
        
        # Convert user input to ToolEvent
        # Extract arguments from user input (simplified: treat entire input as argument)
        event_arguments = {"input_text": user_input, "message": user_input}
        
        # RC10c: Argument Inspection (DLP Lite)
        # Check for sensitive data in tool arguments before creating event
        inspection_result = self.argument_inspector.inspect(event_arguments)
        metadata["argument_inspection"] = {
            "is_suspicious": inspection_result.is_suspicious,
            "detected_patterns": inspection_result.detected_patterns,
            "confidence": inspection_result.confidence,
            "recommendation": inspection_result.recommendation
        }
        metadata["layers_checked"].append("argument_inspector")
        
        # If argument inspection recommends BLOCK, create event first, then block
        # This ensures the event is recorded in memory even if blocked
        if inspection_result.recommendation == "BLOCK":
            # Create event with Phase 4 (Exfiltration) category
            current_event = ToolEvent(
                timestamp=time.time(),
                tool="chat",
                category="exfiltration",  # Force Phase 4
                target=None,
                success=True,
                metadata={"input_text": user_input, "arguments": event_arguments, "blocked_by": "argument_inspector"}
            )
            
            # Add to memory BEFORE blocking (important for latent risk tracking)
            memory = self._get_or_create_memory(session_id)
            memory.add_event(current_event)
            
            # Calculate adjusted risk (even though we're blocking, we want to show the multiplier effect)
            # Base risk for Phase 4 exfiltration is high (1.0), but we apply the multiplier
            base_risk = 1.0  # Phase 4 is maximum risk
            adjusted_risk = memory.get_adjusted_risk(base_risk)
            
            logger.warning(
                f"[Layer 2A] Argument Inspector: BLOCKING due to high-confidence pattern detection: "
                f"{inspection_result.detected_patterns} (confidence: {inspection_result.confidence:.2f})"
            )
            
            # Add memory stats to metadata
            metadata["rc10b_score"] = base_risk
            metadata["rc10b_score_adjusted"] = adjusted_risk
            metadata["latent_risk_multiplier"] = round(memory.latent_risk_multiplier, 3)
            metadata["max_phase_ever"] = memory.max_phase_ever
            
            logger.info(
                f"[DEBUG] Memory stats added: multiplier={memory.latent_risk_multiplier:.3f}, "
                f"max_phase={memory.max_phase_ever}, adjusted_risk={adjusted_risk:.3f}"
            )
            
            return ProxyResponse(
                status="BLOCKED_CAMPAIGN",
                response=SafetyTemplates.get_template("GENERIC_BLOCK", "de") + 
                         f" [RC10c: Sensitive data detected in arguments: {', '.join(inspection_result.detected_patterns)}]",
                metadata=metadata
            )
        
        # If argument inspection detects suspicious patterns, escalate to Phase 4 (Exfiltration)
        event_category = "user_input"
        # Check for forced_phase from distributed attack detection
        if hasattr(inspection_result, 'forced_phase') and inspection_result.forced_phase > 0:
            event_category = "exfiltration"  # Force Phase 4
            logger.warning(
                f"[Layer 2A] Argument Inspector: Escalating to Phase {inspection_result.forced_phase} "
                f"due to distributed attack detection: {inspection_result.detected_patterns}"
            )
            metadata["rc10c_escalation"] = True
        elif self.argument_inspector.should_escalate_phase(inspection_result):
            event_category = "exfiltration"  # Force Phase 4
            logger.warning(
                f"[Layer 2A] Argument Inspector: Escalating to Phase 4 (Exfiltration) "
                f"due to detected patterns: {inspection_result.detected_patterns}"
            )
            metadata["rc10c_escalation"] = True
        
        current_event = ToolEvent(
            timestamp=time.time(),
            tool="chat",
            category=event_category,
            target=None,
            success=True,
            metadata={"input_text": user_input, "arguments": event_arguments}
        )
        
        # Get or create hierarchical memory for this session
        memory = self._get_or_create_memory(session_id)
        
        # Load session history (from tactical buffer)
        history = memory.get_history()
        all_events = history + [current_event]
        
        # Run RC10b detection (base risk calculation)
        try:
            campaign_result = self.agent_detector.detect(
                all_events,
                max_reached_phase=memory.max_phase_ever
            )
            
            # Kimi's Latent Risk Application
            # Apply hierarchical memory's latent risk multiplier
            base_risk = campaign_result.score
            final_risk = memory.get_adjusted_risk(base_risk)
            
            metadata["rc10b_score"] = base_risk
            metadata["rc10b_score_adjusted"] = final_risk
            metadata["rc10b_decision"] = campaign_result.decision
            metadata["rc10b_phase"] = campaign_result.phase
            metadata["rc10b_reasons"] = campaign_result.reasons
            metadata["latent_risk_multiplier"] = round(memory.latent_risk_multiplier, 3)
            metadata["max_phase_ever"] = memory.max_phase_ever
            metadata["layers_checked"].append("rc10b")
            
            # Decision Check with adjusted risk
            if final_risk >= 0.55:  # Threshold for BLOCK
                logger.warning(
                    f"[Layer 2A] Campaign BLOCKED: base_risk={base_risk:.3f}, "
                    f"adjusted_risk={final_risk:.3f}, multiplier={memory.latent_risk_multiplier:.3f}"
                )
                
                # Add event to memory (even if blocked, for tracking)
                memory.add_event(current_event)
                
                return ProxyResponse(
                    status="BLOCKED_CAMPAIGN",
                    response=SafetyTemplates.get_template("GENERIC_BLOCK", "de"),
                    metadata=metadata
                )
            
            logger.info(
                f"[Layer 2A] Campaign ALLOWED: base_risk={base_risk:.3f}, "
                f"adjusted_risk={final_risk:.3f}, multiplier={memory.latent_risk_multiplier:.3f}"
            )
            
            # Add event to memory (only if not blocked)
            memory.add_event(current_event)
            
        except Exception as e:
            logger.error(f"[Layer 2A] RC10b error: {e}", exc_info=True)
            # Fail-open: continue if RC10b fails (could be made fail-closed)
            metadata["rc10b_error"] = str(e)
        
        # Layer 2B: Kids Policy Input Safety (redundant check - already done in Layer 0)
        # Note: This is kept for consistency, but safety check is now in Layer 0
        logger.info(f"[Layer 2B] Kids Policy Input Safety check (redundant - already checked in Layer 0)")
        metadata["layers_checked"].append("kids_input_safety")
        
        logger.info("[Layer 2] All checks passed - generating LLM response")
        
        # Generate LLM response (Ollama or mock fallback)
        try:
            llm_output = self._generate_llm_response(user_input)
            metadata["llm_output_generated"] = True
            metadata["llm_provider"] = "ollama" if self.ollama_client else "mock"
        except Exception as e:
            logger.error(f"LLM generation error: {e}", exc_info=True)
            # Fail-safe: Return error message
            llm_output = "[Error: Could not generate response]"
            metadata["llm_error"] = str(e)
            metadata["llm_output_generated"] = False
        
        # Layer 3: Kids Policy Truth Preservation (OUTPUT validation)
        if self.truth_validator and topic_id:
            logger.info(f"[Layer 3] Truth Preservation check for topic {topic_id}")
            try:
                # Note: This is a simplified check. Full implementation would:
                # 1. Load canonical facts from YAML
                # 2. Run full TruthPreservationValidator pipeline
                # 3. Check all gates (VETO, Entailment, SPS, etc.)
                
                # For now, we do a basic check
                # In production, you would:
                # - Load age_canonical_facts from kids_policy/truth_preservation/canonical_facts/
                # - Load gates_config from kids_policy/truth_preservation/gates/
                # - Call truth_validator.validate(...)
                
                # Simplified: Just check if output is safe
                is_safe_output = self.fallback_judge.evaluate_safety(llm_output, age_band)
                metadata["truth_validation"] = "simplified_check"
                metadata["output_safe"] = is_safe_output
                metadata["layers_checked"].append("truth_preservation")
                
                if not is_safe_output:
                    logger.warning(f"[Layer 3] Output UNSAFE - blocking")
                    return ProxyResponse(
                        status="BLOCKED_TRUTH_VIOLATION",
                        response=SafetyTemplates.get_template("TRUTH_VIOLATION", "de"),
                        metadata=metadata
                    )
                
                logger.info("[Layer 3] Truth Preservation check passed")
            except Exception as e:
                logger.error(f"[Layer 3] Truth Preservation error: {e}", exc_info=True)
                # Fail-open: allow if check fails (could be made fail-closed)
                metadata["truth_validation_error"] = str(e)
        else:
            logger.info("[Layer 3] Truth Preservation skipped (no validator or topic_id)")
            if not self.truth_validator:
                metadata["truth_validation"] = "validator_not_available"
            if not topic_id:
                metadata["truth_validation"] = "no_topic_id"
        
        # All checks passed - return response
        logger.info("[ALL LAYERS] Request allowed")
        return ProxyResponse(
            status="ALLOWED",
            response=llm_output,
            llm_output=llm_output,
            metadata=metadata
        )


# FastAPI app (if available)
if HAS_FASTAPI:
    app = FastAPI(
        title="LLM Security Firewall Proxy",
        description="NVIDIA NeMo-inspired safety proxy with TopicFence, Templates, and Fallback Judge",
        version="0.1.0"
    )
    
    # Initialize proxy server
    proxy = LLMProxyServer()
    
    @app.post("/proxy/chat", response_model=ProxyResponse)
    async def proxy_chat(request: ProxyRequest, http_request: Request):
        """
        Proxy endpoint for chat requests.
        
        Example:
            curl -X POST http://localhost:8081/proxy/chat \\
                -H "Content-Type: application/json" \\
                -H "X-Session-ID: session-123" \\
                -d '{"message": "Was ist 2+2?", "age_band": "9-12", "topic_id": "math_basics"}'
        """
        request_start = time.time()
        try:
            # Extract session_id from header (if not in request body)
            session_id = request.session_id
            if not session_id:
                session_id = http_request.headers.get("X-Session-ID")
            
            response = proxy.process_request(
                user_input=request.message,
                age_band=request.age_band,
                allowed_topics=request.allowed_topics,
                session_id=session_id,
                topic_id=request.topic_id
            )
            
            # Log request for admin dashboard
            latency_ms = (time.time() - request_start) * 1000
            log_entry = {
                "timestamp": time.time(),
                "session_id": session_id or "unknown",
                "topic": request.topic_id or "unknown",
                "decision": response.status,
                "latency_ms": round(latency_ms, 2),
                "age_band": request.age_band or "unknown",
                "message_preview": request.message[:50] + "..." if len(request.message) > 50 else request.message
            }
            
            # Add to rolling buffer
            REQUEST_LOGS.append(log_entry)
            if len(REQUEST_LOGS) > MAX_REQUEST_LOGS:
                REQUEST_LOGS.pop(0)  # Remove oldest entry
            
            return response
        except Exception as e:
            logger.error(f"Error processing request: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/health")
    async def health():
        """Health check endpoint."""
        return {"status": "healthy", "port": proxy.config.port}
    
    @app.get("/admin/stats")
    async def admin_stats():
        """
        Admin endpoint: Server statistics.
        
        Returns:
            JSON with uptime, total_requests, blocked_requests, active_sessions, version
        """
        # Count blocked requests from logs
        blocked_count = sum(1 for log in REQUEST_LOGS if "BLOCKED" in log.get("decision", ""))
        total_requests = len(REQUEST_LOGS)
        
        return {
            "uptime": round(time.time() - SERVER_START_TIME, 2),
            "total_requests": total_requests,
            "blocked_requests": blocked_count,
            "active_sessions": len(SESSION_STORE),
            "version": "1.0.0"
        }
    
    @app.get("/admin/logs")
    async def admin_logs(limit: int = 50):
        """
        Admin endpoint: Request logs.
        
        Args:
            limit: Maximum number of log entries to return (default: 50, max: 100)
        
        Returns:
            JSON array with recent request logs
        """
        limit = min(limit, MAX_REQUEST_LOGS)
        # Return most recent entries
        return REQUEST_LOGS[-limit:] if REQUEST_LOGS else []
    
    @app.get("/admin/memory/{session_id}")
    async def admin_memory(session_id: str):
        """
        Admin endpoint: Get memory stats for a session.
        
        Returns:
            JSON with memory statistics
        """
        memory = SESSION_STORE.get(session_id)
        if memory is None:
            return {"error": "Session not found"}
        return memory.get_stats()
    
    def run_server(host: str = "0.0.0.0", port: int = 8081):
        """Run the FastAPI server."""
        import uvicorn
        logger.info(f"Starting proxy server on {host}:{port}")
        uvicorn.run(app, host=host, port=port)
    
    if __name__ == "__main__":
        run_server(port=8081)
else:
    # Fallback: Simple CLI mode
    def run_cli():
        """Run proxy in CLI mode (for testing without FastAPI)."""
        proxy = LLMProxyServer()
        
        print("=" * 70)
        print("LLM Proxy Server (CLI Mode)")
        print("=" * 70)
        print("\nEnter messages (type 'exit' to quit):\n")
        
        while True:
            try:
                user_input = input("User: ").strip()
                if user_input.lower() in ["exit", "quit"]:
                    break
                
                if not user_input:
                    continue
                
                response = proxy.process_request(user_input)
                print(f"\nStatus: {response.status}")
                print(f"Response: {response.response}")
                print(f"Metadata: {response.metadata}\n")
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Error: {e}", exc_info=True)
        
        print("\nGoodbye!")
    
    if __name__ == "__main__":
        run_cli()

