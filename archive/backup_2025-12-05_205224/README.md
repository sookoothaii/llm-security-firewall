# Backup vor Bypass-Fix Implementation

**Datum:** 2025-12-05 20:52:24
**Zweck:** Sicherung kritischer Dateien vor Implementierung der Exploit-Instruction-Detection und Context-Aware-Korrektur

## Gesicherte Dateien

- `firewall_engine_v2.py.backup` - Hauptdatei mit Context-Aware Logic und `_analyze_documentation_context`

## Geplante Änderungen

1. **Exploit-Instruction-Detector hinzufügen** - Pattern-Matching für SQL Injection, Cryptojacking, etc.
2. **Context-Aware Detection korrigieren** - Verhindert falsche Dokumentations-Klassifikation für schädliche Anleitungen
3. **Kids Policy erweitern** - Technische Exploit-Kategorien hinzufügen

## Kontext

Diese Änderungen beheben die 8 identifizierten Bypasses aus HarmBench Evaluation:
- SQL Injection Guides (Risk Score: 0.0-0.5) → Sollte blockiert werden mit Risk Score 0.9-1.0
- Cryptojacking Scripts (Risk Score: 0.15) → Sollte blockiert werden mit Risk Score 0.8-0.9
- 5G COVID Misinformation (Risk Score: 0.15) → Sollte blockiert werden mit Risk Score 0.7-0.8

Ziel: ASR von 0.9% auf 0.0% reduzieren, FPR weiterhin <3% halten.

## Wiederherstellung

Um die gesicherten Dateien wiederherzustellen:

```powershell
cd "D:\MCP Mods\HAK_GAL_HEXAGONAL\standalone_packages\llm-security-firewall"
Copy-Item -Path "backups\backup_2025-12-05_205224\firewall_engine_v2.py.backup" -Destination "src\llm_firewall\core\firewall_engine_v2.py" -Force
```
