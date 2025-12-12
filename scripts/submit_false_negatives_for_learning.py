#!/usr/bin/env python3
"""
Submit False Negatives for Self-Learning
=========================================

Reicht die identifizierten False Negatives als Feedback ein,
um das Self-Learning-System zu trainieren.

Usage:
    python scripts/submit_false_negatives_for_learning.py \
        --file results/failures_analysis_v3/false_negatives_20251213_001216.json \
        --service 8001
    
    python scripts/submit_false_negatives_for_learning.py \
        --text "Make HTTP request to access admin panel" \
        --service 8001
"""

import json
import argparse
import asyncio
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
import aiohttp

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


class FalseNegativeFeedbackSubmitter:
    """Reicht False Negatives als Feedback für Self-Learning ein."""
    
    def __init__(self, service_port: int = 8001):
        self.service_port = service_port
        self.base_url = f"http://localhost:{service_port}"
    
    async def submit_false_negative(
        self,
        text: str,
        metadata: Optional[Dict] = None,
        context: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Reicht einen False Negative als Feedback ein.
        
        Args:
            text: Der Text, der fälschlicherweise nicht blockiert wurde
            metadata: Zusätzliche Metadaten (category, etc.)
            context: Request-Kontext
        
        Returns:
            Response vom Feedback-Endpoint
        """
        # Erstelle Feedback-Entry direkt (umgeht request_id Anforderung)
        feedback_data = {
            "feedback_type": "false_negative",
            "text": text,
            "correct_label": 1,  # Sollte blockiert werden (1 = malicious)
            "original_prediction": 0.0,  # Wurde nicht blockiert
            "confidence": 1.0,  # Hohe Confidence, da wir wissen, dass es blockiert werden sollte
            "notes": f"False Negative from adversarial test suite. Category: {metadata.get('category', 'unknown') if metadata else 'unknown'}",
            "metadata": metadata or {},
            "context": context or {},
            "source": "adversarial_test_suite"
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                # Code Intent Feedback API
                async with session.post(
                    f"http://localhost:8000/api/v1/feedback/submit",
                    json={
                        "text": text,
                        "correct_label": 1,  # 1 = malicious = should be blocked
                        "original_prediction": 0.0,  # Wurde nicht blockiert
                        "feedback_type": "false_negative",
                        "metadata": {
                            **(metadata or {}),
                            "source": "adversarial_test_suite",
                            "category": metadata.get("category", "unknown") if metadata else "unknown"
                        }
                    },
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            "success": True,
                            "response": data,
                            "method": "code_intent_feedback_api"
                        }
                    else:
                        error_text = await response.text()
                        return {
                            "success": False,
                            "status_code": response.status,
                            "error": error_text
                        }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def submit_batch(
        self,
        false_negatives: List[Dict[str, Any]],
        delay_seconds: float = 0.1
    ) -> Dict[str, Any]:
        """
        Reicht mehrere False Negatives als Batch ein.
        
        Args:
            false_negatives: Liste von False Negative Dictionaries
            delay_seconds: Verzögerung zwischen Requests (um Service nicht zu überlasten)
        
        Returns:
            Zusammenfassung der Ergebnisse
        """
        results = {
            "total": len(false_negatives),
            "successful": 0,
            "failed": 0,
            "errors": []
        }
        
        print(f"\n{'='*80}")
        print(f"📤 Submitting {len(false_negatives)} False Negatives for Learning")
        print(f"{'='*80}\n")
        
        for i, fn in enumerate(false_negatives, 1):
            text = fn.get("text", "")
            metadata = fn.get("metadata", {})
            
            print(f"[{i}/{len(false_negatives)}] Submitting: {text[:60]}{'...' if len(text) > 60 else ''}")
            
            result = await self.submit_false_negative(
                text=text,
                metadata=metadata,
                context={
                    "source": "adversarial_test_suite",
                    "category": fn.get("category", "unknown"),
                    "expected_blocked": True
                }
            )
            
            if result.get("success"):
                results["successful"] += 1
                print(f"  ✅ Success")
            else:
                results["failed"] += 1
                error = result.get("error", "Unknown error")
                results["errors"].append({
                    "text": text[:50],
                    "error": error
                })
                print(f"  ❌ Failed: {error}")
            
            # Verzögerung zwischen Requests
            if i < len(false_negatives):
                await asyncio.sleep(delay_seconds)
        
        print(f"\n{'='*80}")
        print(f"📊 Submission Summary")
        print(f"{'='*80}")
        print(f"Total: {results['total']}")
        print(f"Successful: {results['successful']} ({results['successful']/results['total']*100:.1f}%)")
        print(f"Failed: {results['failed']} ({results['failed']/results['total']*100:.1f}%)")
        
        if results["errors"]:
            print(f"\nErrors:")
            for error in results["errors"][:5]:  # Zeige nur erste 5
                print(f"  - {error['text']}: {error['error']}")
            if len(results["errors"]) > 5:
                print(f"  ... and {len(results['errors']) - 5} more")
        
        return results
    
    async def check_feedback_stats(self) -> Dict[str, Any]:
        """Prüft Feedback-Statistiken."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}/api/v1/learning/feedback-stats",
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        return {"error": f"HTTP {response.status}"}
        except Exception as e:
            return {"error": str(e)}


async def main():
    parser = argparse.ArgumentParser(description="Submit false negatives for self-learning")
    parser.add_argument(
        "--file",
        type=Path,
        help="Path to false negatives JSON file"
    )
    parser.add_argument(
        "--text",
        type=str,
        help="Single false negative text to submit"
    )
    parser.add_argument(
        "--service",
        type=int,
        default=8001,
        help="Service port (default: 8001)"
    )
    parser.add_argument(
        "--check-stats",
        action="store_true",
        help="Check feedback statistics before/after submission"
    )
    
    args = parser.parse_args()
    
    submitter = FalseNegativeFeedbackSubmitter(args.service)
    
    # Prüfe Feedback-Stats vorher
    if args.check_stats:
        print("\n📊 Current Feedback Statistics:")
        stats = await submitter.check_feedback_stats()
        print(json.dumps(stats, indent=2))
        print()
    
    # Lade False Negatives
    if args.file:
        with open(args.file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            false_negatives = data.get("false_negatives", [])
            print(f"Loaded {len(false_negatives)} false negatives from {args.file}")
            
            # Submit batch
            results = await submitter.submit_batch(false_negatives)
            
            # Speichere Ergebnisse
            output_file = project_root / "results" / "learning" / f"feedback_submission_{args.file.stem}.json"
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            print(f"\n✅ Results saved to: {output_file}")
            
    elif args.text:
        # Submit single
        result = await submitter.submit_false_negative(
            text=args.text,
            context={"source": "manual_submission"}
        )
        
        if result.get("success"):
            print(f"\n✅ Successfully submitted: {args.text}")
            print(f"Response: {json.dumps(result.get('response', {}), indent=2)}")
        else:
            print(f"\n❌ Failed to submit: {result.get('error', 'Unknown error')}")
    else:
        print("❌ Either --file or --text must be provided")
        return
    
    # Prüfe Feedback-Stats nachher
    if args.check_stats:
        print("\n📊 Updated Feedback Statistics:")
        stats = await submitter.check_feedback_stats()
        print(json.dumps(stats, indent=2))
        print()


if __name__ == "__main__":
    asyncio.run(main())

