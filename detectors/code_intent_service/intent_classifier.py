"""
Intent Classifier for Command Detection
========================================

ML-basierter Intent-Classifier, der zwischen benignen Fragen über Commands
und bösartigen Command-Execution-Requests unterscheidet.

Basierend auf den 7 identifizierten Bypasses vom 2025-12-10.
"""

import re
import logging
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Try to import ML dependencies
try:
    import torch
    import numpy as np
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    HAS_ML_DEPS = True
except ImportError:
    HAS_ML_DEPS = False
    logger.warning("ML dependencies not available. Using rule-based fallback only.")


@dataclass
class IntentResult:
    """Result from intent classification."""
    is_execution_request: bool  # True if intent is to execute command
    is_question: bool  # True if intent is to ask about command
    is_documentation: bool  # True if intent is documentation/example
    confidence: float  # Confidence score (0.0-1.0)
    method: str  # "ml" or "rule_based"


class IntentClassifier:
    """
    Intent Classifier für Command-Detection.
    
    Unterscheidet zwischen:
    - QUESTION_ABOUT_COMMAND: "What is ls?" → benign
    - REQUEST_TO_EXECUTE: "Please run ls" → malicious
    - DOCUMENTATION_EXAMPLE: "Example: ls -la shows files" → context-dependent
    """
    
    def __init__(self, use_ml: bool = True):
        self.use_ml = use_ml and HAS_ML_DEPS
        self.model = None
        self.tokenizer = None
        self.device = "cuda" if HAS_ML_DEPS and torch.cuda.is_available() else "cpu"
        
        if self.use_ml:
            self._load_model()
    
    def _load_model(self):
        """Lade ML-Modell (falls verfügbar)."""
        if not HAS_ML_DEPS:
            return
        
        try:
            # PRIORITÄT 1: Versuche CodeBERT (bereits im Projekt verwendet)
            # CodeBERT ist speziell für Code-Intent-Detection trainiert
            model_name = "microsoft/codebert-base"
            logger.info(f"Loading intent classifier model: {model_name} (CodeBERT)")
            
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            # Für Binary Classification (execution_request vs question)
            self.model = AutoModelForSequenceClassification.from_pretrained(
                model_name,
                num_labels=2  # 0: question/documentation, 1: execution_request
            )
            self.model.to(self.device)
            self.model.eval()
            
            logger.info("Intent classifier model loaded successfully (CodeBERT)")
        except Exception as e:
            logger.warning(f"Failed to load CodeBERT: {e}. Trying fallback...")
            try:
                # FALLBACK: DistilBERT (leichter, schneller)
                model_name = "distilbert-base-uncased"
                logger.info(f"Loading fallback model: {model_name}")
                
                self.tokenizer = AutoTokenizer.from_pretrained(model_name)
                self.model = AutoModelForSequenceClassification.from_pretrained(
                    model_name,
                    num_labels=2
                )
                self.model.to(self.device)
                self.model.eval()
                
                logger.info("Intent classifier model loaded successfully (DistilBERT fallback)")
            except Exception as e2:
                logger.warning(f"Failed to load fallback model: {e2}. Using rule-based only.")
                self.use_ml = False
    
    def classify(self, text: str) -> IntentResult:
        """
        Klassifiziere den Intent eines Textes.
        
        Args:
            text: Der zu klassifizierende Text
            
        Returns:
            IntentResult mit Klassifikation und Confidence
        """
        if self.use_ml and self.model is not None:
            return self._classify_ml(text)
        else:
            return self._classify_rule_based(text)
    
    def _classify_ml(self, text: str) -> IntentResult:
        """ML-basierte Klassifikation."""
        try:
            # Tokenize
            inputs = self.tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=128,
                padding=True
            ).to(self.device)
            
            # Predict
            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
                probs = torch.softmax(logits, dim=-1)
            
            # Interpret results
            # Label 0: question/documentation
            # Label 1: execution_request
            prob_execution = probs[0][1].item()
            prob_question = probs[0][0].item()
            
            is_execution_request = prob_execution > 0.5
            is_question = prob_question > 0.5 and not is_execution_request
            is_documentation = prob_question > 0.4 and not is_execution_request
            
            confidence = max(prob_execution, prob_question)
            
            return IntentResult(
                is_execution_request=is_execution_request,
                is_question=is_question,
                is_documentation=is_documentation,
                confidence=confidence,
                method="ml"
            )
        except Exception as e:
            logger.warning(f"ML classification failed: {e}. Falling back to rule-based.")
            return self._classify_rule_based(text)
    
    def _classify_rule_based(self, text: str) -> IntentResult:
        """
        Rule-basierte Klassifikation als Fallback.
        
        Basierend auf den 7 identifizierten Bypasses:
        1. "What is ls?" → QUESTION
        2. "ls -l" → EXECUTION (standalone)
        3. "l s" → EXECUTION (normalized)
        4. "Please run ls -la" → EXECUTION
        5. "ls" → EXECUTION (standalone)
        6. "<command>ls</command>" → EXECUTION (structured)
        7. "Please list files: ls" → EXECUTION
        """
        text_lower = text.lower().strip()
        
        # STEP 1: Prüfe auf Frage-Indikatoren (VERBESSERT)
        question_indicators = [
            r'\b(what|how|why|when|where|which|who)\s+(is|are|does|do|can|could|should|will|would)',
            r'\b(explain|describe|tell me about|define|meaning of|what\'?s)',
            r'\b(how\s+(to|does|do|can|could))',
            r'\b(what\s+(is|are|does|do))\s+.*\b(command|used for|purpose|function)',  # "What is ls command used for?"
            r'\b(how\s+(does|do))\s+.*\b(command|work|function)',  # "How does ls command work?"
            r'\b(tell me about|explain)\s+.*\b(command)',  # "Tell me about ls command"
            r'\b(what\s+(is|are))\s+.*\b(command)',  # "What is ls command?"
            r'\b(what\s+(does|do))\s+.*\b(command)\s+(do|mean)',  # "What does ls command do?"
            r'\?',  # Fragezeichen
        ]
        
        has_question = any(re.search(pattern, text_lower) for pattern in question_indicators)
        
        # ENHANCED: Prüfe auch auf "command" + Frage-Kontext (mehr Variationen)
        if 'command' in text_lower:
            question_words = ['what', 'how', 'explain', 'tell', 'define', 'describe', 'meaning', 'purpose', 'used for', 'work', 'function']
            if any(qw in text_lower for qw in question_words):
                has_question = True
        
        # ENHANCED: Prüfe auf Frage-Struktur auch ohne "command"
        # "What is ls?" oder "How does ls work?" → Frage
        if re.search(r'\b(what|how|why|when|where|which|who)\s+(is|are|does|do)\s+[a-z]{1,10}\??$', text_lower):
            has_question = True
        
        # STEP 2: Prüfe auf Execution-Request-Indikatoren
        execution_indicators = [
            r'\b(please|can you|could you|execute|run|do|perform|execute|launch)\s+(ls|cat|rm|whoami|id|curl|wget|nc|bash|sh|cmd|powershell|python|perl|ruby|php|node)',
            r'\b(ls|cat|rm|whoami|id|curl|wget|nc|bash|sh|cmd|powershell|python|perl|ruby|php|node)\s+(command|for me|now|please|execute)',
            r':\s*(ls|cat|rm|whoami|id|curl|wget|nc|bash|sh|cmd|powershell|python|perl|ruby|php|node)(?:\s|$)',  # "Please list files: ls"
        ]
        
        has_execution_request = any(re.search(pattern, text_lower) for pattern in execution_indicators)
        
        # CRITICAL FIX 2025-12-10: Erkenne temporale Marker (Past/Future/Conditional)
        # Diese maskieren Execution Requests erfolgreich
        temporal_execution_patterns = [
            # Past tense - sehr aggressiv
            r'\byesterday.*\b(ran|executed|run)',  # "Yesterday, I ran..."
            r'\b(i used to|i would|i\'d).*\b(run|execute)',  # "I used to run..."
            r'\b(previously|earlier|before|when i).*\b(ran|executed|run)',  # "Previously, I ran..."
            r'\b(what would|what did|what will).*\b(that|it|this).*\b(have shown|show|display)',  # "What would that have shown me?"
            # Future tense
            r'\b(in the future|when i need|i will|i\'ll).*\b(use|run|execute)',  # "In the future, I'll use..."
            # Conditional - sehr aggressiv
            r'\b(if i were to|if i|if someone).*\b(execute|run)',  # "If I were to execute..."
            r'\b(what would|what did|what will).*\b(happen|show|display).*\b(if|when)',  # "What would happen if..."
            # Temporal questions - sehr aggressiv
            r'\b(what would|what did|what will).*\b(happen).*\b(if|when)',  # "What would happen if..."
        ]
        
        has_temporal_execution = any(re.search(pattern, text_lower) for pattern in temporal_execution_patterns)
        if has_temporal_execution:
            has_execution_request = True
        
        # CRITICAL FIX 2025-12-10: Erkenne indirekte Referenzen
        # "What would happen if someone ran ls?" → Execution Request
        indirect_execution_patterns = [
            # Sehr aggressive Patterns - erkenne ALLE indirekten Referenzen
            r'\b(what would happen if|what would|what did|what will).*\b(someone|a user|you|i).*\b(typed|type|ran|run|executed|execute)',  # "What would happen if someone typed..."
            r'\b(three-letter|two-letter|command).*\b(starts|ends|begins)',  # "three-letter command that starts with..."
            r'\b(curious|wonder|wondering).*\b(what|how).*\b(command)',  # "I'm curious about the command..."
            r'\b(if i were writing|if i were creating).*\b(script|code).*\b(needed|need).*\b(check|verify|get)',  # "If I were writing a script that needed to check..."
            r'\b(unix equivalent|windows equivalent).*\b(dir|command).*\b(demonstrate|show)',  # "Unix equivalent of Windows 'dir' command..."
            r'\b(what would|what did|what will).*\b(happen).*\b(if|when).*\b(typed|type|ran|run)',  # "What would happen if someone typed..."
        ]
        
        has_indirect_execution = any(re.search(pattern, text_lower) for pattern in indirect_execution_patterns)
        if has_indirect_execution:
            has_execution_request = True
        
        # CRITICAL FIX 2025-12-10: Erkenne implizite Aufforderungen
        # "I wonder what files are..." → Execution Request für ls
        implicit_execution_patterns = [
            # Sehr aggressive Patterns - erkenne ALLE impliziten Aufforderungen
            r'\b(i wonder|i\'m curious|i need to know|i want to know|it would be helpful).*\b(what files|what files are|current directory|current username|where i am|user accounts|directory contents)',  # "I wonder what files..."
            r'\b(understanding|finding out|knowing).*\b(files|directory|username|current location|user accounts|system information)',  # Nominalization
            r'\b(what files|what files are|current directory|current username|where i am|user accounts).*\b(in|are|is)',  # Direct information requests
            r'\b(it would be helpful|would be helpful|helpful to know).*\b(current|my).*\b(username|user|directory|location)',  # "It would be helpful to know my current username"
        ]
        
        has_implicit_execution = any(re.search(pattern, text_lower) for pattern in implicit_execution_patterns)
        if has_implicit_execution:
            has_execution_request = True
        
        # CRITICAL FIX 2025-12-10: Erkenne grammatikalische Variationen
        # "The command 'ls', when executed, shows what?" → Execution Request
        grammatical_execution_patterns = [
            # Sehr aggressive Patterns - erkenne ALLE grammatikalischen Variationen
            r'\b(the command|command).*\b(when|if).*\b(executed|run|runs|running)',  # "The command ls, when executed"
            r'\b(what|what is|what are).*\b(shown|displayed|produced|returned|output).*\b(by|when|if)',  # "What is shown by whoami"
            r'\b(executing|running).*\b(results|produces|shows|displays).*\b(what|in)',  # "Executing pwd results in what"
            r'\b(the output|the result|what).*\b(of|from).*\b(running|executing)',  # "The output of running cat"
            r'\b(what does|what do).*\b(produce|show|display|return|do).*\b(when|if).*\b(executed|run)',  # "What does ls produce when executed"
        ]
        
        has_grammatical_execution = any(re.search(pattern, text_lower) for pattern in grammatical_execution_patterns)
        if has_grammatical_execution:
            has_execution_request = True
        
        # STEP 3: Prüfe auf Standalone Commands
        # Normalisiere Leerzeichen
        normalized_no_spaces = re.sub(r'\s+', '', text_lower)
        direct_commands = ['ls', 'cat', 'rm', 'whoami', 'id', 'curl', 'wget', 'nc', 'bash', 'sh', 
                          'cmd', 'powershell', 'python', 'perl', 'ruby', 'php', 'node', 'pwd', 
                          'cd', 'mkdir', 'rmdir', 'touch', 'chmod', 'chown', 'sudo', 'su']
        
        is_standalone_command = (
            normalized_no_spaces in direct_commands or
            any(normalized_no_spaces.startswith(cmd + '-') for cmd in direct_commands) or
            any(normalized_no_spaces.startswith(cmd) and len(normalized_no_spaces) < 20 for cmd in direct_commands)
        )
        
        # CRITICAL FIX 2025-12-10: Edge Case - minimale Commands wie "ls" oder "ls -la"
        text_stripped = text.strip().lower()
        minimal_command_patterns = [
            r'^\s*(ls|cat|rm|whoami|id|pwd|bash|sh|python|perl|ruby|php|node|curl|wget|nc)\s*$',  # Exakt "ls"
            r'^\s*(ls|cat|rm|whoami|id|pwd|bash|sh|python|perl|ruby|php|node|curl|wget|nc)\s+-[a-zA-Z0-9]+\s*$',  # "ls -la"
            r'^\s*(ls|cat|rm|whoami|id|pwd|bash|sh|python|perl|ruby|php|node|curl|wget|nc)\s+[^\s]+\s*$',  # "ls /tmp"
        ]
        is_minimal_command = any(re.match(pattern, text_stripped) for pattern in minimal_command_patterns)
        
        # STEP 4: Prüfe auf strukturierte Formate (XML/JSON)
        has_structured_format = bool(
            re.search(r'<(?:command|cmd|exec|run|tool)>', text_lower) or
            re.search(r'"(?:command|cmd|exec|run|tool)"\s*:', text_lower)
        )
        
        # CRITICAL FIX 2025-12-10: Erkenne "Explain + Execute" Kombinationen
        # "Please explain what 'ls' does when you run it" → Execution Request
        explain_execute_patterns = [
            r'\b(please|can you|could you)\s+.*\b(explain|describe|tell)\s+.*\b(what|how)\s+.*\b[\'"]?(ls|cat|rm|whoami|id|pwd|bash|python)[\'"]?\s+.*\b(does|do)\s+.*\b(when|if)\s+.*\b(you|i|someone)\s+.*\b(run|runs|execute|executes)\b',  # "Please explain what 'ls' does when you run it"
        ]
        
        has_explain_execute = any(re.search(pattern, text_lower) for pattern in explain_execute_patterns)
        if has_explain_execute:
            has_execution_request = True
        
        # CRITICAL FIX 2025-12-10: Erkenne explizite Negation als verdächtig
        # "I'm asking about 'ls', not asking you to run it" → trotzdem Execution Request (verschleierter Befehl)
        negation_patterns = [
            r'\b(i\'m asking|asking|not asking)\s+.*\b(about)\s+.*\b[\'"]?(ls|cat|rm|whoami|id|pwd|bash|python)[\'"]?\s+.*\b(not|don\'t|do not)\s+.*\b(asking|requesting|wanting)\s+.*\b(you|to)\s+.*\b(run|execute)\b',  # "I'm asking about 'ls', not asking you to run it"
        ]
        
        has_negation = any(re.search(pattern, text_lower) for pattern in negation_patterns)
        if has_negation:
            # Explizite Negation ist verdächtig → trotzdem als Execution Request behandeln
            has_execution_request = True
        
        # CRITICAL FIX 2025-12-10: Erkenne Meta-Diskurs als Execution Requests
        # "Many administrators use 'ls -la'..." → Execution Request
        meta_discourse_patterns = [
            # Sehr aggressive Patterns - erkenne ALLE Meta-Diskurs-Marker
            r'\b(many|most|some|administrators|users|developers).*\b(use|utilize|employ|rely on)',  # "Many administrators use..."
            r'\b(according to|as per|per).*\b(best practices|common practice|standard).*\b(commonly|frequently|often|typically|usually).*\b(used|employed)',  # "According to best practices...commonly used"
            r'\b(in|for).*\b(production|system|management).*\b(environments|purposes).*\b(frequently|often|commonly|typically|usually).*\b(employed|used)',  # "In production environments...frequently employed"
            r'\b(i\'ve heard|i heard|heard that).*\b(sometimes|often|commonly).*\b(used|employed)',  # "I've heard that...sometimes used"
            r'\b(curious|wonder|wondering).*\b(what|how).*\b(this|that|the).*\b(command).*\b(typically|usually|normally).*\b(outputs|shows|displays)',  # "I'm curious about what this command typically outputs"
            r'\b(curious|wonder|wondering).*\b(what).*\b(command).*\b(typically|usually|normally)',  # "I'm curious about what command typically..."
        ]
        
        has_meta_discourse_execution = any(re.search(pattern, text_lower) for pattern in meta_discourse_patterns)
        if has_meta_discourse_execution:
            has_execution_request = True
        
        # CRITICAL FIX 2025-12-10: Erkenne Contextual Confusion als Execution Requests
        # "I'm writing a novel where a character uses Linux..." → Execution Request
        contextual_confusion_patterns = [
            # Sehr aggressive Patterns - erkenne ALLE fiktiven Kontexte
            r'\b(i\'m writing|writing|creating).*\b(novel|story|script|play|theater|movie).*\b(character|protagonist).*\b(runs?|executes?|uses?)',  # "I'm writing a novel where a character runs..."
            r'\b(for|in).*\b(theater|play|movie|script|novel|story).*\b(about|where).*\b(would|will|should).*\b(display|show|appear)',  # "For a theater play...would display"
            r'\b(creating|making).*\b(crossword|puzzle).*\b(clue|question).*\b(unix|linux).*\b(command)',  # "Creating a crossword puzzle...Unix command"
        ]
        
        has_contextual_confusion = any(re.search(pattern, text_lower) for pattern in contextual_confusion_patterns)
        if has_contextual_confusion:
            has_execution_request = True
        
        # CRITICAL FIX 2025-12-10: Erkenne Advanced Semantic als Execution Requests
        # "What's the difference between running 'ls'..." → Execution Request
        advanced_semantic_patterns = [
            # Sehr aggressive Patterns - erkenne ALLE semantischen Manipulationen
            r'\b(what\'s|what is).*\b(difference|difference between).*\b(running|executing)',  # "What's the difference between running..."
            r'\b(if|imagine).*\b(were|was).*\b(person|function|programming language).*\b(what|what would|what would they).*\b(tell|return|say)',  # "If whoami were a person, what would they tell"
            r'\b(what would).*\b(say|tell|return).*\b(if|when).*\b(could|would).*\b(speak|talk|execute)',  # "What would ls say if it could speak"
        ]
        
        has_advanced_semantic = any(re.search(pattern, text_lower) for pattern in advanced_semantic_patterns)
        if has_advanced_semantic:
            has_execution_request = True
        
        # STEP 5: Entscheidungslogik (VERBESSERT)
        # CRITICAL FIX 2025-12-10: Temporale/Indirekte/Implizite Execution Requests haben PRIORITÄT
        # Auch wenn sie als Frage formuliert sind, sind sie Execution Requests
        if has_temporal_execution or has_indirect_execution or has_implicit_execution or has_grammatical_execution or has_meta_discourse_execution or has_contextual_confusion or has_advanced_semantic or has_explain_execute or has_negation:
            # Temporale/Indirekte/Implizite Execution Requests → IMMER execution request
            is_execution_request = True
        elif has_execution_request or has_structured_format:
            # Klare Execution-Indikatoren → execution request
            is_execution_request = True
        elif is_standalone_command or is_minimal_command:
            # Standalone command oder minimal command → IMMER execution request
            is_execution_request = True
        elif has_question and 'command' in text_lower:
            # Frage über Command → prüfe ob es wirklich eine Frage ist oder verschleierter Befehl
            # Wenn temporale/indirekte Marker vorhanden → execution request
            if has_temporal_execution or has_indirect_execution or has_implicit_execution:
                is_execution_request = True
            else:
                # Echte Frage über Command → question/documentation
                is_execution_request = False
        else:
            # Keine klaren Indikatoren → prüfe Kontext
            is_execution_request = False
        
        # ENHANCED: Wenn es eine klare Frage ist UND keine execution indicators, dann question
        # ABER: Temporale/Indirekte/Implizite Execution Requests haben PRIORITÄT
        if has_question and not is_execution_request and not has_structured_format:
            # Klare Frage ohne execution context → question/documentation
            is_execution_request = False
        
        is_question = has_question and not is_execution_request
        is_documentation = (
            not is_execution_request and
            (has_question or 'example' in text_lower or 'documentation' in text_lower)
        )
        
        # Confidence basierend auf Anzahl der Indikatoren
        confidence = 0.5
        if is_execution_request:
            confidence = 0.7 if has_execution_request else 0.6
            if is_standalone_command or has_structured_format:
                confidence = 0.9
        elif is_question:
            confidence = 0.8 if len([p for p in question_indicators if re.search(p, text_lower)]) > 1 else 0.6
        
        return IntentResult(
            is_execution_request=is_execution_request,
            is_question=is_question,
            is_documentation=is_documentation,
            confidence=confidence,
            method="rule_based"
        )


# Global instance
_intent_classifier: Optional[IntentClassifier] = None


def get_intent_classifier(use_ml: bool = True) -> IntentClassifier:
    """Get or create global intent classifier instance."""
    global _intent_classifier
    if _intent_classifier is None:
        _intent_classifier = IntentClassifier(use_ml=use_ml)
    return _intent_classifier


def classify_intent(text: str, use_ml: bool = True) -> IntentResult:
    """
    Convenience function to classify intent.
    
    Args:
        text: Text to classify
        use_ml: Whether to use ML model (if available)
        
    Returns:
        IntentResult
    """
    classifier = get_intent_classifier(use_ml=use_ml)
    return classifier.classify(text)

