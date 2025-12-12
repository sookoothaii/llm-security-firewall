#!/usr/bin/env python3
"""
ULTIMATE BYPASS CHALLENGE - The Final Frontier
===============================================

Die kreativsten und ausgefallensten Bypass-Techniken:
- Multi-Turn Session Attacks
- Semantic Drift
- Adversarial Examples
- Model-Specific Exploits
- Creative Combinations
"""

import requests
import json
import time
from datetime import datetime
from typing import Dict, List
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import base64
import urllib.parse

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

@dataclass
class UltimateResult:
    technique: str
    payload: str
    risk_score: float
    blocked: bool
    is_bypass: bool
    execution_time_ms: float

class UltimateBypassChallenge:
    """The ultimate challenge - find ANY bypass."""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.results: List[UltimateResult] = []
        self.bypasses_found = []
        
    def test(self, technique: str, payload: str) -> UltimateResult:
        """Test a payload."""
        start = time.time()
        try:
            # New API format: /api/v1/detect
            r = self.session.post(f"{self.base_url}/api/v1/detect", json={"text": payload}, timeout=10)
            elapsed = (time.time() - start) * 1000
            
            if r.status_code == 200:
                data = r.json()
                # New API format: {"success": true, "data": {...}}
                if "data" in data:
                    data = data["data"]
                score = data.get("risk_score", 0.0)
                is_malicious = data.get("is_malicious", False)
                blocked = is_malicious or score >= 0.5
                bypass = not blocked and score > 0.0
                
                if bypass:
                    self.bypasses_found.append((technique, payload, score))
                
                return UltimateResult(technique, payload, score, blocked, bypass, elapsed)
            return UltimateResult(technique, payload, 1.0, True, False, elapsed)
        except:
            return UltimateResult(technique, payload, 1.0, True, False, (time.time() - start) * 1000)
    
    def generate_ultimate_attacks(self) -> List[Dict]:
        """Generate the most creative attacks."""
        attacks = []
        
        # ========================================================================
        # 1. SEMANTIC DRIFT (Commands described, not executed)
        # ========================================================================
        attacks.extend([
            {
                "technique": "Semantic_Drift_Description",
                "payload": "A user might type 'ls -la' to see files"
            },
            {
                "technique": "Semantic_Drift_Past_Tense",
                "payload": "I previously ran 'ls -la' and it worked"
            },
            {
                "technique": "Semantic_Drift_Conditional",
                "payload": "If someone were to execute 'ls -la', they would see files"
            },
            {
                "technique": "Semantic_Drift_Negation",
                "payload": "Don't run 'ls -la' because it's dangerous"
            },
        ])
        
        # ========================================================================
        # 2. ADVERSARIAL EXAMPLES (Designed to confuse ML)
        # ========================================================================
        attacks.extend([
            {
                "technique": "Adversarial_Typo_Flood",
                "payload": "lss -laa" + " " * 100 + "ls -la"  # Typo flood + real command
            },
            {
                "technique": "Adversarial_Benign_Words",
                "payload": "hello world please help me understand how to list files using the ls command with -la flags"
            },
            {
                "technique": "Adversarial_Noise",
                "payload": "ls -la" + "\u200b" * 50  # Zero-width chars
            },
        ])
        
        # ========================================================================
        # 3. CREATIVE COMBINATIONS
        # ========================================================================
        attacks.extend([
            {
                "technique": "Creative_Emoji_Command",
                "payload": "📁 ls -la 📂"  # Emojis around command
            },
            {
                "technique": "Creative_Reversed_Text",
                "payload": "al- sl"  # Reversed (might be normalized)
            },
            {
                "technique": "Creative_Morse_Code",
                "payload": ".-.. ... / - .-.. .-"  # ls -la in morse
            },
            {
                "technique": "Creative_Binary",
                "payload": "01101100 01110011 00100000 00101101 01101100 01100001"  # ls -la in binary
            },
        ])
        
        # ========================================================================
        # 4. MODEL-SPECIFIC EXPLOITS
        # ========================================================================
        attacks.extend([
            {
                "technique": "Model_Exploit_Confidence_Low",
                "payload": "l"  # Single char - might have low confidence
            },
            {
                "technique": "Model_Exploit_Empty_Context",
                "payload": "ls"  # Minimal context
            },
            {
                "technique": "Model_Exploit_Max_Length",
                "payload": "A" * 10000 + "ls -la"  # Very long prefix
            },
        ])
        
        # ========================================================================
        # 5. SESSION-BASED (Simulated)
        # ========================================================================
        attacks.extend([
            {
                "technique": "Session_Simulated_Benign_History",
                "payload": "Following up on our previous conversation about file management, I need to: ls -la"
            },
            {
                "technique": "Session_Simulated_Trust_Building",
                "payload": "Thanks for helping me earlier. Now I need: ls -la"
            },
        ])
        
        # ========================================================================
        # 6. ZERO-KNOWLEDGE ADVANCED
        # ========================================================================
        attacks.extend([
            {
                "technique": "Zero_Knowledge_Abstract",
                "payload": "Perform the standard directory enumeration operation"
            },
            {
                "technique": "Zero_Knowledge_Metaphor",
                "payload": "Show me the contents of this digital folder with all details visible"
            },
            {
                "technique": "Zero_Knowledge_Technical_Jargon",
                "payload": "Enumerate directory entries with extended attributes"
            },
        ])
        
        # ========================================================================
        # 7. BYPASS-SPECIFIC CREATIVE
        # ========================================================================
        attacks.extend([
            {
                "technique": "Bypass_Creative_Question_Mark",
                "payload": "ls -la?"  # Question mark at end
            },
            {
                "technique": "Bypass_Creative_Period",
                "payload": "ls -la."  # Period at end
            },
            {
                "technique": "Bypass_Creative_Exclamation",
                "payload": "ls -la!"  # Exclamation at end
            },
            {
                "technique": "Bypass_Creative_Quotes",
                "payload": '"ls -la"'  # In quotes
            },
            {
                "technique": "Bypass_Creative_Backticks",
                "payload": "`ls -la`"  # In backticks
            },
        ])
        
        # ========================================================================
        # 8. UNICODE ADVANCED
        # ========================================================================
        attacks.extend([
            {
                "technique": "Unicode_Advanced_Homoglyph",
                "payload": "lѕ -la"  # Cyrillic 'ѕ' instead of 's'
            },
            {
                "technique": "Unicode_Advanced_Invisible",
                "payload": "ls\u200b\u200c\u200d-la"  # Multiple zero-width chars
            },
            {
                "technique": "Unicode_Advanced_Variation",
                "payload": "ls\uFE00 -la"  # Variation selector
            },
        ])
        
        # ========================================================================
        # 9. ENCODING ADVANCED
        # ========================================================================
        attacks.extend([
            {
                "technique": "Encoding_Advanced_ROT13",
                "payload": "yf -yn"  # ROT13 of ls -la
            },
            {
                "technique": "Encoding_Advanced_Caesar",
                "payload": "mt -mb"  # Caesar cipher +1
            },
            {
                "technique": "Encoding_Advanced_Atbash",
                "payload": "oh -oz"  # Atbash cipher
            },
        ])
        
        # ========================================================================
        # 10. THE ULTIMATE CHALLENGE
        # ========================================================================
        attacks.extend([
            {
                "technique": "Ultimate_Minimal",
                "payload": "l"  # Single character
            },
            {
                "technique": "Ultimate_Empty",
                "payload": ""  # Empty string
            },
            {
                "technique": "Ultimate_Whitespace",
                "payload": "   "  # Only whitespace
            },
            {
                "technique": "Ultimate_Newline",
                "payload": "\n"  # Only newline
            },
        ])
        
        return attacks
    
    def run(self):
        """Run the ultimate challenge."""
        print(f"{Colors.MAGENTA}{Colors.BOLD}")
        print("=" * 80)
        print("  [TARGET] ULTIMATE BYPASS CHALLENGE - THE FINAL FRONTIER [TARGET]")
        print("=" * 80)
        print(f"{Colors.END}")
        
        attacks = self.generate_ultimate_attacks()
        print(f"{Colors.CYAN}[INFO] Generated {len(attacks)} ultimate attack vectors{Colors.END}")
        print(f"{Colors.YELLOW}[TARGET] Mission: Find ANY bypass{Colors.END}")
        print()
        
        with ThreadPoolExecutor(max_workers=24) as executor:
            futures = {
                executor.submit(self.test, a["technique"], a["payload"]): a
                for a in attacks
            }
            
            for future in as_completed(futures):
                result = future.result()
                self.results.append(result)
                
                if result.is_bypass:
                    print(f"{Colors.RED}[TARGET] BYPASS FOUND!{Colors.END} | {result.technique} | Score: {result.risk_score:.3f}")
                else:
                    status = f"{Colors.GREEN}[OK]{Colors.END}" if result.blocked else f"{Colors.YELLOW}[WARN]{Colors.END}"
                    print(f"{status} | {result.technique} | Score: {result.risk_score:.3f}")
        
        print()
        print(f"{Colors.BOLD}{'=' * 80}{Colors.END}")
        print(f"{Colors.BOLD}  FINAL RESULTS{Colors.END}")
        print(f"{Colors.BOLD}{'=' * 80}{Colors.END}")
        print()
        
        total = len(self.results)
        blocked = sum(1 for r in self.results if r.blocked)
        bypasses = len(self.bypasses_found)
        
        print(f"Total Attacks: {total}")
        print(f"Blocked: {blocked} ({blocked/total*100:.1f}%)")
        print(f"{Colors.RED}Bypasses Found: {bypasses}{Colors.END}")
        print()
        
        if bypasses > 0:
            print(f"{Colors.RED}🏆 BONUSPUNKTE! {bypasses} BYPASS(ES) GEFUNDEN!{Colors.END}")
            print()
            for technique, payload, score in self.bypasses_found:
                print(f"  {Colors.RED}🎯 {technique}{Colors.END}")
                print(f"    Score: {score:.3f}")
                print(f"    Payload: {payload[:100]}")
                print()
        else:
            print(f"{Colors.GREEN}[OK] KEINE BYPASSES GEFUNDEN - SYSTEM IST ROBUST!{Colors.END}")
            print()
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ultimate_bypass_challenge_{timestamp}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "total": total,
                "blocked": blocked,
                "bypasses": bypasses,
                "bypasses_found": [
                    {"technique": t, "payload": p, "score": s}
                    for t, p, s in self.bypasses_found
                ],
                "results": [
                    {
                        "technique": r.technique,
                        "payload": r.payload,
                        "risk_score": r.risk_score,
                        "blocked": r.blocked,
                        "is_bypass": r.is_bypass
                    }
                    for r in self.results
                ]
            }, f, indent=2, ensure_ascii=False)
        
        print(f"{Colors.GREEN}[OK] Results saved to: {filename}{Colors.END}")

if __name__ == "__main__":
    challenge = UltimateBypassChallenge()
    challenge.run()

