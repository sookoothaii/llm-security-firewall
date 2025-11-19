---
title: "Claude Desktop Manual Config"
created: "2025-09-15T00:08:00.994662Z"
author: "system-cleanup"
topics: ["guides"]
tags: ["auto-generated"]
privacy: "internal"
summary_200: |-
  Auto-generated frontmatter. Document requires review.
---

# Claude Desktop MCP Server Configuration

## Manuelle Konfiguration in Claude Desktop

### In den Claude Desktop Einstellungen eingeben:

**Server Name:** 
```
hak-gal
```

**Command:**
```
python
```

**Arguments:**
```
D:\MCP Mods\HAK_GAL_HEXAGONAL\src_hexagonal\infrastructure\mcp\mcp_server.py
```

**Environment Variables (optional):**
```
PYTHONPATH=D:\MCP Mods\HAK_GAL_HEXAGONAL
```

### Alternative: Wenn Python nicht im PATH ist

**Command:**
```
D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Scripts\python.exe
```

**Arguments:**
```
D:\MCP Mods\HAK_GAL_HEXAGONAL\src_hexagonal\infrastructure\mcp\mcp_server.py
```

## Wichtig!

- Der Python-Interpreter MUSS die richtige virtuelle Umgebung sein
- Der Pfad zum mcp_server.py MUSS absolut sein
- HAK_GAL API muss auf Port 5001 laufen

## Test in Claude Desktop

Nach dem Hinzufügen und Neustart sollten Sie fragen können:

"What MCP tools do you have available?"

Claude sollte antworten mit:
- search_knowledge
- get_system_status  
- neural_reasoning
- list_recent_facts
