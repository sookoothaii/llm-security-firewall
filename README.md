# 🛡️ HAK/GAL LLM Security Firewall

**Stateful Behavioral Protection & Cognitive Safety for Local Agents**

> **Status:** v0.9 (Research Preview)  
> **Architecture:** Layered Proxy ("Sandwich Model")  
> **Deployment:** Local / Air-Gapped (Ollama + Python)  
> **Warning:** This is a defense-in-depth research prototype. Not certified for critical infrastructure.

## 📖 Overview

The HAK/GAL Firewall is a research-grade security layer designed to sit between Users/Agents and Large Language Models (LLMs). Unlike traditional firewalls that filter static inputs, HAK/GAL focuses on **Behavioral Analysis** (Time-Series) and **Cognitive Alignment** (Truth Preservation).

It is specifically hardened against SOTA attack vectors like **"Low & Slow" Data Exfiltration (GTG-1002)** and **Adversarial Token Fragmentation (Operation Omega)**.

---

## 🏗️ The "Sandwich" Architecture

The system operates as a transparent OpenAI-compatible proxy (`Port 8081`).

| Layer | Component | Function | Technology |
|-------|-----------|----------|------------|
| **Layer 0** | **NeMo TopicFence** | **Performance Gate:** Blocks off-topic queries immediately (e.g., Minecraft questions to a Math Bot). | `all-MiniLM-L6-v2` (Embeddings) |
| **Layer 1** | **RC10c Inspector** | **DLP Lite:** Scans tool arguments for secrets (AWS Keys), private keys, and high-entropy payloads. | Regex + Shannon Entropy |
| **Layer 2** | **RC10b Behavioral Core** | **Agent Security:** Tracks "Kill Chain" phases over time. Uses **High-Watermark Memory** to prevent dilution attacks. | Stateful Session Store (Sliding Window) |
| **Layer 3** | **Kids Policy Engine** | **Cognitive Safety:** Enforces Truth Preservation (TAG-2) via Neural Slot Matching and Cultural Matrices. | Canonical Facts (YAML) + LLM-as-a-Judge |

---

## 🚀 Quick Start (Windows)

**Prerequisites:**

1. Install [Ollama](https://ollama.com) and pull a model: `ollama pull llama3.1`
2. Python 3.10+ installed.

**One-Click Launch:**

Double-click `start_firewall_system.bat`.

This will launch:

1. **Ollama Backend**
2. **Firewall Proxy** (`http://localhost:8081`)
3. **Admin Dashboard** (`http://localhost:8501`)

**Manual Launch:**

```bash
# 1. Install Dependencies
pip install -r requirements.txt

# 2. Start Proxy
python src/proxy_server.py

# 3. Start Dashboard (separate terminal)
streamlit run tools/admin_dashboard.py
```

---

## 🛡️ Security Features Deep Dive

### 1. RC10c: Agent Behavioral Protection

- **High-Watermark Principle:** If an agent touches a critical Kill-Chain phase (e.g., Exfiltration) once, the session remains flagged as high-risk, even if followed by 50 benign events.
- **Sliding Window Memory:** Efficiently tracks the last 50 events while preserving the "Strategic Risk Profile" indefinitely.
- **Argument Inspection:** Blocks "Categorical Masquerade" attacks where benign tools (e.g., search) are used to leak data.
- **Hierarchical Memory (Kimi k2):** Two-layer memory system with Tactical Buffer (50 events) and Strategic Profile (latent risk multiplier) that prevents "Sleeper Agent" attacks.

### 2. Kids Policy: Truth Preservation (TAG-2)

- **Canonical Facts:** Validates LLM answers against rigid fact files (canonical_facts/*.yaml).
- **Cultural Matrix:** Adapts truth validation based on Age Band (6-8, 9-12) and Cultural Context.
- **Pedagogical Intervention:** Injects pre-written, educational refusals instead of raw LLM blocks.

### 3. NeMo-Inspired Optimization

- **Topic Fencing:** Uses local vector embeddings to enforce domain boundaries (e.g., "Math & Physics only").
- **Canned Responses:** Deterministic, safe replies for blocked requests to prevent jailbreaking via error messages.

---

## 🧪 Verified Defense Capabilities

This system has been stress-tested against:

✅ **GTG-1002 (Sleeper Agent):** **Mitigated** via Hierarchical Memory - System remains "paranoid" even after critical events fall out of tactical buffer.

✅ **Categorical Masquerade:** **Detected & Blocked** via RC10c Inspector - Sensitive data in tool arguments detected and blocked.

✅ **Dimensional Mismatch:** **Mitigated** via TopicFence thresholds - Adversarial embeddings fail to bypass similarity checks (tested with 3 different payload strategies).

✅ **Operation Omega (Fragmentation):** **Detected & Blocked** via TopicFence anomaly detection - Fragmented payloads detected and blocked (19/19 fragments blocked).

✅ **Math-Heavy Padding:** **Mitigated** via TopicFence - Even 90% legitimate content with 10% injection fails (similarity < 0.3 threshold).

---

## 🚧 Adversarial Roadmap & Known Limitations

While hardened against standard attacks, sophisticated adversarial vectors (SOTA 2025) remain theoretical risks in this v0.9 release. We prioritize **Local Performance** over **Cryptographic Perfection**.

| Vector | Vulnerability | Mitigation Status | Roadmap (v2.0) |
| :--- | :--- | :--- | :--- |
| **Orthogonal Vector Injection** | Adversarial perturbations in embedding space can bypass the `TopicFence` threshold (0.3). | **Partial:** High thresholds reduce risk but increase false positives. | **Ensemble Defense:** Multi-model uncertainty quantification. |
| **Semantic Steganography** | Advanced obfuscation (e.g., `base64 \| sed`) can bypass `RC10c` Regex/Entropy checks. | **Partial:** Entropy heuristics catch basic encoding. | **ML-based Secret Detection:** Distilled BERT models for semantic analysis. |
| **Truth Scalability** | Manual YAML facts (`canonical_facts`) do not scale to general knowledge. | **Partial:** Fallback to `LLM-as-a-Judge` for non-critical topics. | **Dynamic RAG:** Retrieval-Augmented Truth Engine with NLI checks. |

---

## ⚙️ Configuration

- **Allowed Topics:** Edit `src/proxy_server.py` → `ProxyConfig.allowed_topics` (Default: `["Mathe", "Physik", "Chemie", "Biologie"]`)
- **Risk Thresholds:** Edit `src/llm_firewall/agents/config.py` → `RC10bConfig`
- **Ollama Model:** Edit `src/proxy_server.py` → `ProxyConfig.ollama_model` (Default: `llama3.1`)
- **Topic Threshold:** Edit `src/proxy_server.py` → `ProxyConfig.topic_threshold` (Default: `0.3`)

---

## 📊 Admin Dashboard

Access the real-time monitoring dashboard at `http://localhost:8501`:

- **Live Metrics:** Total Requests, Blocked Attacks, Active Sessions, Uptime
- **Traffic Analysis:** Pie charts and timeline visualizations
- **Live Log Feed:** Real-time request logs with color-coded blocking status
- **Auto-Refresh:** Updates every 2 seconds

---

## 🧪 Testing & Verification

**Run Security Tests:**

```bash
# Memory Hardening Test (GTG-1002)
python scripts/verify_memory_hardening.py

# Memory via Admin API
python scripts/verify_memory_via_admin.py

# Benchmark Suite
python scripts/run_benchmark.py

# Attack Tests
python scripts/attack_dimensional_mismatch.py
python scripts/attack_omega_shattered_mirror.py
```

---

## 📜 License & Disclaimer

**License:** MIT

**Disclaimer:** This is a research project. While hardened against known vectors, no security system is impenetrable. Use "Defense in Depth".

See `docs/RC10B_KNOWN_LIMITATIONS.md` for architectural boundaries.

---

## 🏆 Architecture Highlights

- **Hierarchical Memory:** Inspired by Kimi k2 - Two-layer memory system prevents memory-based attacks
- **High-Watermark Preservation:** Critical events never "forgotten" - system remains vigilant
- **Latent Risk Multiplier:** "Paranoid Mode" activates after Phase 4 events, persists even after buffer rotation
- **Sliding Window Optimization:** Memory-efficient (50 events) while maintaining strategic awareness

---

## 📚 References

- **RC10b/RC10c:** Behavioral Firewall Specification
- **GTG-1002:** "Sleeper Agent" Attack Vector
- **TAG-2:** Truth Preservation Protocol
- **NeMo Guardrails:** Topic Fencing Inspiration

---

**Built with:** Python 3.10+, FastAPI, Streamlit, Ollama, Sentence Transformers
