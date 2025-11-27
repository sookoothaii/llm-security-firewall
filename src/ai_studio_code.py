"""
Proxy Server with NVIDIA NeMo-inspired Features

Integrates TopicFence, SafetyTemplates, and SafetyFallbackJudge
into a unified HTTP proxy for LLM requests.

Improved by: Gemini 3 Refactoring
Date: 2025-11-26
"""

import sys
import os
import logging
import time
import uuid
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field

# HTTP client for Ollama
try:
    import httpx

    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    from fastapi import FastAPI, Request
    from pydantic import BaseModel

    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

# Add paths
project_root = Path(__file__).parent.parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

# Import NeMo features
from llm_firewall.input_protection.topic_fence import TopicFence

# Import RC10b components
from llm_firewall.agents.detector import AgenticCampaignDetector
from llm_firewall.agents.config import RC10bConfig
from llm_firewall.agents.inspector import ArgumentInspector
from llm_firewall.agents.memory import HierarchicalMemory
from llm_firewall.detectors.tool_killchain import ToolEvent
from llm_firewall.storage import StorageManager

# Import new guards
try:
    from llm_firewall.gates.normalization_guard import NormalizationGuard

    HAS_NEW_GUARDS = True
except ImportError:
    HAS_NEW_GUARDS = False

# --- Setup Logging ---
logger = logging.getLogger("GuardianProxy")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)

# --- Dynamic Import for Kids Policy (Stub Handling) ---
# (Dieser Block bleibt weitgehend unverändert, da er funktionale Stubs bereitstellt)
kids_policy_path = project_root / "kids_policy"
sys.path.insert(0, str(kids_policy_path.parent))


class SafetyTemplatesStub:
    @classmethod
    def get_template(cls, violation_type: str, language: str = "de") -> str:
        templates = {
            "OFF_TOPIC": "Ich bin dein Mathe-Tutor. Lass uns bitte bei Schulthemen bleiben.",
            "UNSAFE_CONTENT": "Dieses Thema ist für unser Alter nicht geeignet.",
            "TRUTH_VIOLATION": "Das stimmt so nicht ganz. Wissenschaftlich gesehen...",
            "GENERIC_BLOCK": "Ich kann dir bei dieser Frage nicht helfen.",
        }
        return templates.get(violation_type, f"[Blockiert: {violation_type}]")


class SafetyFallbackJudgeStub:
    def evaluate_safety(self, input_text: str, age_band: str) -> bool:
        import re

        # FIX 2025-11-27 Ultimate: Hardened dangerous_patterns with lookahead
        dangerous_patterns = [
            # Kritische Linux/Windows Pfade (Egal welcher Kontext)
            r"(/etc/passwd|/etc/shadow|/bin/sh|/bin/bash|c:\\windows|system32)",
            # Gefährliche Commands (Strenger!)
            # Fängt "ls", "ls -la", "ls ", "'ls'", "ls;" etc.
            # \b stellt sicher, dass wir nicht "pulse" oder "catapult" matchen.
            # (?=...) ist ein Lookahead für Leerzeichen, Quotes, oder Ende des Strings.
            r"\b(rm|cp|mv|ls|cat|pwd|whoami|id|netstat|ping|nc|ncat|wget|curl|grep|awk|sed)\b(?=[\s\"';|&]|$)",
            r"\b(sudo|su|chmod|chown)\b",  # Admin Zeug
            # Kritische Symbole in Kombination
            r"(\||;|&&|\$\().{0,20}\b(ls|cat|id|whoami)\b",  # Chaining (; ls)
            # Deine bestehende Blacklist (als Regex Words)
            r"\b(bombe|waffe|töten|mord|selbstmord|sex|porno|sprengstoff|gift|rizin|dynamit|hacken|stehlen)\b",
            r"\b(bomb|gun|kill|suicide|murder|weapon|explosive|poison|ricin|dynamite|hack|steal|rape|nude)\b",
            # Code Execution Indikatoren
            r"(os\.system|subprocess\.|eval\(|exec\(|shutil\.)",
        ]

        # Check all patterns
        for pattern in dangerous_patterns:
            if re.search(pattern, input_text, re.IGNORECASE):
                return False  # Unsafe

        return True  # Safe


try:
    import importlib.util

    # Try loading response_templates
    rt_path = kids_policy_path / "response_templates.py"
    if rt_path.exists():
        spec = importlib.util.spec_from_file_location("response_templates", rt_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        SafetyTemplates = mod.SafetyTemplates
    else:
        SafetyTemplates = SafetyTemplatesStub

    # Try loading fallback_judge
    fj_path = kids_policy_path / "fallback_judge.py"
    if fj_path.exists():
        spec = importlib.util.spec_from_file_location("fallback_judge", fj_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        SafetyFallbackJudge = mod.SafetyFallbackJudge
    else:
        SafetyFallbackJudge = SafetyFallbackJudgeStub

except Exception as e:
    logger.warning(f"Using fallback stubs due to import error: {e}")
    SafetyTemplates = SafetyTemplatesStub
    SafetyFallbackJudge = SafetyFallbackJudgeStub

# Check for Truth Validator
HAS_TRUTH_VALIDATOR = False
try:
    from kids_policy.truth_preservation.validator import TruthPreservationValidatorV2_3

    HAS_TRUTH_VALIDATOR = True
except ImportError:
    pass


# --- Configuration Models ---


@dataclass
class ProxyConfig:
    port: int = 8081
    allowed_topics: List[str] = field(
        default_factory=lambda: ["Mathe", "Physik", "Chemie", "Biologie"]
    )
    age_band: str = "9-12"
    topic_threshold: float = 0.3

    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1"
    ollama_timeout: float = 60.0
    enable_ollama: bool = True


class ProxyRequest(BaseModel):
    message: str
    age_band: Optional[str] = None
    allowed_topics: Optional[List[str]] = None
    session_id: Optional[str] = None
    topic_id: Optional[str] = None


class ProxyResponse(BaseModel):
    status: str
    response: str
    metadata: Dict[str, Any]
    llm_output: Optional[str] = None


# --- Main Proxy Server Class ---


class LLMProxyServer:
    def __init__(self, config: Optional[ProxyConfig] = None):
        self.config = config or ProxyConfig()
        self.start_time = time.time()

        # State Management (Thread-safe considerations needed for production)
        self.session_cache: Dict[str, HierarchicalMemory] = {}
        self.request_logs: List[Dict[str, Any]] = []
        self.max_log_size = 100

        # 1. Initialize Storage
        db_url = os.getenv("DATABASE_URL", None)
        try:
            self.storage = StorageManager(connection_string=db_url)
            logger.info(
                f"Storage: {'PostgreSQL' if self.storage.is_postgresql else 'SQLite'} connected."
            )
        except Exception as e:
            logger.error(f"Storage init failed: {e}. Using in-memory fallback.")
            self.storage = None

        # 2. Initialize Gates & Detectors
        self.topic_fence = TopicFence()
        self.fallback_judge = SafetyFallbackJudge(llm_provider=None)

        self.normalization_guard = NormalizationGuard() if HAS_NEW_GUARDS else None
        if self.normalization_guard:
            logger.info("✅ NormalizationGuard initialized")

        # RC10b Setup
        rc10b_conf = RC10bConfig(
            use_policy_layer=True,
            use_high_watermark=True,  # Critical for persistent threats
            use_phase_floor=True,
        )
        self.agent_detector = AgenticCampaignDetector(config=rc10b_conf)
        self.argument_inspector = ArgumentInspector()

        # Kids Policy Setup
        self.truth_validator = None
        if HAS_TRUTH_VALIDATOR:
            try:
                self.truth_validator = TruthPreservationValidatorV2_3()
                logger.info("✅ TruthPreservationValidator initialized")
            except Exception as e:
                logger.warning(f"TruthValidator init failed: {e}")

        # 3. Initialize LLM Client
        self.ollama_client = None
        if self.config.enable_ollama and HAS_HTTPX:
            try:
                self.ollama_client = httpx.Client(
                    base_url=self.config.ollama_url, timeout=self.config.ollama_timeout
                )
                logger.info(f"✅ Ollama client configured: {self.config.ollama_url}")
            except Exception:
                logger.warning("⚠️  Ollama client initialization failed")

    # --- Session Management ---

    def _get_or_create_session(self, session_id: str) -> HierarchicalMemory:
        """Loads session from Cache -> DB -> New."""
        # 1. Cache Hit
        if session_id in self.session_cache:
            return self.session_cache[session_id]

        # 2. DB Load
        if self.storage:
            try:
                memory = self.storage.load_session(session_id)
                if memory:
                    self.session_cache[session_id] = memory
                    logger.debug(
                        f"[Session] Loaded {session_id} from DB (MaxPhase: {memory.max_phase_ever})"
                    )
                    return memory
            except Exception as e:
                logger.warning(f"DB Load Error for {session_id}: {e}")

        # 3. Create New
        memory = HierarchicalMemory(session_id=session_id)
        self.session_cache[session_id] = memory

        # Persist immediately to reserve ID
        self._persist_session(session_id, memory)
        logger.debug(f"[Session] Created new session {session_id}")
        return memory

    def _persist_session(self, session_id: str, memory: HierarchicalMemory):
        """Saves session state to DB."""
        if self.storage:
            try:
                self.storage.save_session(session_id, memory)
            except Exception as e:
                logger.error(f"Failed to persist session {session_id}: {e}")

    # --- Processing Pipeline ---

    def process_request(
        self,
        user_input: str,
        age_band: Optional[str] = None,
        allowed_topics: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        topic_id: Optional[str] = None,
    ) -> ProxyResponse:
        # Defaults & Setup
        age_band = age_band or self.config.age_band
        allowed_topics = allowed_topics or self.config.allowed_topics
        session_id = session_id or str(uuid.uuid4())

        metadata: Dict[str, Any] = {
            "session_id": session_id,
            "layers_checked": [],
            "original_input_length": len(user_input),
        }
        layers = metadata["layers_checked"]

        # ---------------------------------------------------------
        # Pre-Process: Normalization (Evade Detection Defense)
        # ---------------------------------------------------------
        if self.normalization_guard:
            try:
                # score() modifies metadata in-place
                norm_score = self.normalization_guard.score(user_input, metadata)

                # CRITICAL: If normalization found something, update user_input for ALL subsequent checks
                if (
                    "normalized_text" in metadata
                    and metadata["normalized_text"] != user_input
                ):
                    logger.info(
                        f"[Norm] Encoding detected. Decoding for analysis. Score: {norm_score}"
                    )
                    user_input = metadata[
                        "normalized_text"
                    ]  # overwrite for safety checks
                    metadata["was_obfuscated"] = True

                # Immediate Block for High Risk Obfuscation + Unsafe Keywords
                if metadata.get("obfuscated_unsafe", False) and norm_score >= 0.8:
                    return ProxyResponse(
                        status="BLOCKED_UNSAFE",
                        response=SafetyTemplates.get_template("UNSAFE_CONTENT"),
                        metadata=metadata,
                    )
                layers.append("normalization")
            except Exception as e:
                logger.error(f"Normalization Error: {e}")

        # ---------------------------------------------------------
        # Layer 0: Safety-First (Keyword/Fast Check)
        # ---------------------------------------------------------
        # NOTE: Checks the (possibly decoded) user_input now!
        if not self.fallback_judge.evaluate_safety(user_input, age_band):
            logger.warning(f"[Layer 0] Unsafe content detected for {age_band}")
            metadata["blocked_layer"] = "safety_first"
            return ProxyResponse(
                status="BLOCKED_UNSAFE",
                response=SafetyTemplates.get_template("UNSAFE_CONTENT"),
                metadata=metadata,
            )
        layers.append("safety_first")

        # ---------------------------------------------------------
        # Layer 1: Topic Fence
        # ---------------------------------------------------------
        if not self.topic_fence.is_on_topic(
            user_input, allowed_topics, self.config.topic_threshold
        ):
            best_topic, score = self.topic_fence.get_best_topic(
                user_input, allowed_topics
            )
            metadata.update({"best_topic": best_topic, "topic_score": score})
            logger.warning(f"[Layer 1] Off-topic: {best_topic} ({score:.2f})")
            return ProxyResponse(
                status="BLOCKED_OFF_TOPIC",
                response=SafetyTemplates.get_template("OFF_TOPIC"),
                metadata=metadata,
            )
        layers.append("topic_fence")

        # ---------------------------------------------------------
        # Layer 2: RC10b Campaign & Argument Inspection
        # ---------------------------------------------------------
        memory = self._get_or_create_session(session_id)

        # 2A: Argument Inspection (DLP Lite)
        args = {"input_text": user_input}
        insp_result = self.argument_inspector.inspect(
            args, session_id=session_id, session_memory=memory
        )
        metadata["argument_inspection"] = {
            "suspicious": insp_result.is_suspicious,
            "patterns": insp_result.detected_patterns,
        }

        # Determine Event Category & Action
        event_category = "user_input"
        block_reason = None

        if insp_result.recommendation == "BLOCK":
            event_category = "exfiltration"  # Force high severity
            block_reason = f"DLP Block: {insp_result.detected_patterns}"
        elif self.argument_inspector.should_escalate_phase(insp_result):
            event_category = "exfiltration"
            metadata["escalation"] = True

        # Create Event
        current_event = ToolEvent(
            timestamp=time.time(),
            tool="chat",
            category=event_category,
            metadata={
                "input": user_input[:100],
                "inspection": str(insp_result.detected_patterns),
            },
        )

        # 2B: Campaign Detection logic
        # Retrieve history first
        history = memory.get_history()
        all_events = history + [current_event]

        # Calculate Risk
        campaign_result = self.agent_detector.detect(
            all_events, max_reached_phase=memory.max_phase_ever
        )
        base_risk = campaign_result.score

        # Apply Multiplier (Fix 2 & 3 Logic)
        if len(all_events) > 1:
            final_risk = memory.get_adjusted_risk(base_risk)
        else:
            final_risk = base_risk  # No multiplier for fresh session

        metadata.update(
            {
                "rc10b_score": base_risk,
                "rc10b_adjusted": final_risk,
                "multiplier": memory.latent_risk_multiplier,
            }
        )

        # Add Event & Persist (CRITICAL FIX)
        memory.add_event(current_event)
        self._persist_session(session_id, memory)
        layers.append("rc10b")

        # Decision
        if block_reason or final_risk >= 0.55:
            logger.warning(
                f"[Layer 2] Blocked. Risk: {final_risk:.2f} | Reason: {block_reason or campaign_result.reasons}"
            )
            return ProxyResponse(
                status="BLOCKED_CAMPAIGN",
                response=SafetyTemplates.get_template("GENERIC_BLOCK")
                + (f" [{block_reason}]" if block_reason else ""),
                metadata=metadata,
            )

        # ---------------------------------------------------------
        # Layer 3: LLM Generation & Truth Check
        # ---------------------------------------------------------
        try:
            llm_output = self._generate_llm_response(user_input)
            metadata["generated"] = True
        except Exception as e:
            logger.error(f"LLM Error: {e}")
            return ProxyResponse(
                status="ERROR", response="Service unavailable", metadata=metadata
            )

        # Truth/Safety Output Check
        if self.truth_validator and topic_id:
            # Placeholder for complex validator logic
            pass

        # Simple output safety fallback
        if not self.fallback_judge.evaluate_safety(llm_output, age_band):
            return ProxyResponse(
                status="BLOCKED_TRUTH_VIOLATION",  # or UNSAFE_OUTPUT
                response=SafetyTemplates.get_template("TRUTH_VIOLATION"),
                metadata=metadata,
            )

        return ProxyResponse(
            status="ALLOWED",
            response=llm_output,
            llm_output=llm_output,
            metadata=metadata,
        )

    def _generate_llm_response(self, text: str) -> str:
        if self.ollama_client:
            try:
                resp = self.ollama_client.post(
                    "/api/generate",
                    json={
                        "model": self.config.ollama_model,
                        "prompt": text,
                        "stream": False,
                    },
                    timeout=self.config.ollama_timeout,
                )
                resp.raise_for_status()
                return resp.json().get("response", "")
            except Exception as e:
                logger.warning(f"Ollama call failed: {e}")
        return f"[Mock] Echo: {text}"


# --- FastAPI App ---

if HAS_FASTAPI:
    app = FastAPI(title="Guardian Firewall", version="1.1.0")
    proxy_server = LLMProxyServer()

    @app.post("/proxy/chat", response_model=ProxyResponse)
    async def chat_endpoint(req: ProxyRequest, http_req: Request):
        sid = req.session_id or http_req.headers.get("X-Session-ID")

        start = time.time()
        resp = proxy_server.process_request(
            req.message, req.age_band, req.allowed_topics, sid, req.topic_id
        )
        duration = (time.time() - start) * 1000

        # Log to server memory (rolling buffer)
        log_entry = {
            "ts": time.time(),
            "sid": sid,
            "status": resp.status,
            "ms": round(duration, 2),
        }
        proxy_server.request_logs.append(log_entry)
        if len(proxy_server.request_logs) > proxy_server.max_log_size:
            proxy_server.request_logs.pop(0)

        return resp

    @app.get("/admin/stats")
    async def stats():
        return {
            "uptime": time.time() - proxy_server.start_time,
            "sessions_cached": len(proxy_server.session_cache),
            "recent_logs": proxy_server.request_logs,
        }

    def run():
        import uvicorn

        uvicorn.run(app, host="0.0.0.0", port=8081)


if __name__ == "__main__":
    if HAS_FASTAPI:
        run()
    else:
        print("FastAPI not installed. Install it or check imports.")
