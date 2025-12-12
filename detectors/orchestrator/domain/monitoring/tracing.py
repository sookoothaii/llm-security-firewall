"""
Distributed Tracing - Phase 5.4

Implementiert Distributed Tracing für Request-Tracking über Services.
"""

import uuid
import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from datetime import datetime
import contextvars
import json
import logging

logger = logging.getLogger(__name__)

# Context variable für Trace-Kontext
trace_context = contextvars.ContextVar('trace_context', default=None)


@dataclass
class Span:
    """Ein einzelner Span im Trace."""
    span_id: str
    trace_id: str
    parent_span_id: Optional[str]
    name: str
    start_time: datetime
    end_time: Optional[datetime]
    duration_ms: Optional[float]
    attributes: Dict[str, Any]
    events: List[Dict[str, Any]]
    status: str  # "success", "error", "timeout"
    error_message: Optional[str]


@dataclass
class Trace:
    """Ein kompletter Trace mit mehreren Spans."""
    trace_id: str
    root_span_id: str
    spans: Dict[str, Span]
    start_time: datetime
    end_time: Optional[datetime]
    metadata: Dict[str, Any]


class TraceCollector:
    """Sammelt und verwaltet Distributed Traces."""

    def __init__(self, export_to_console: bool = False):
        self.traces: Dict[str, Trace] = {}
        self.export_to_console = export_to_console
        self.active_spans: Dict[str, Span] = {}

    def start_trace(self, name: str, metadata: Dict[str, Any] = None) -> str:
        """Startet einen neuen Trace."""
        trace_id = str(uuid.uuid4())
        span_id = str(uuid.uuid4())

        span = Span(
            span_id=span_id,
            trace_id=trace_id,
            parent_span_id=None,
            name=f"root:{name}",
            start_time=datetime.utcnow(),
            end_time=None,
            duration_ms=None,
            attributes=metadata or {},
            events=[],
            status="success",
            error_message=None
        )

        trace = Trace(
            trace_id=trace_id,
            root_span_id=span_id,
            spans={span_id: span},
            start_time=span.start_time,
            end_time=None,
            metadata=metadata or {}
        )

        self.traces[trace_id] = trace
        self.active_spans[span_id] = span

        # Setze Context
        context = {
            "trace_id": trace_id,
            "span_id": span_id,
            "parent_span_id": None
        }
        trace_context.set(context)

        if self.export_to_console:
            logger.info(f"Trace started: {trace_id}, Span: {span_id}, Name: {name}")

        return trace_id

    def start_span(self, name: str, attributes: Dict[str, Any] = None) -> str:
        """Startet einen neuen Span im aktuellen Trace."""
        context = trace_context.get()
        if not context:
            # Starte neuen Trace wenn keiner aktiv
            return self.start_trace(name, attributes)

        trace_id = context["trace_id"]
        parent_span_id = context["span_id"]
        span_id = str(uuid.uuid4())

        span = Span(
            span_id=span_id,
            trace_id=trace_id,
            parent_span_id=parent_span_id,
            name=name,
            start_time=datetime.utcnow(),
            end_time=None,
            duration_ms=None,
            attributes=attributes or {},
            events=[],
            status="success",
            error_message=None
        )

        if trace_id in self.traces:
            self.traces[trace_id].spans[span_id] = span
        else:
            # Sollte nicht passieren, aber als Fallback
            trace = Trace(
                trace_id=trace_id,
                root_span_id=span_id,
                spans={span_id: span},
                start_time=span.start_time,
                end_time=None,
                metadata={}
            )
            self.traces[trace_id] = trace

        self.active_spans[span_id] = span

        # Update Context
        context["span_id"] = span_id
        context["parent_span_id"] = parent_span_id
        trace_context.set(context)

        if self.export_to_console:
            logger.info(f"Span started: {span_id}, Parent: {parent_span_id}, Name: {name}")

        return span_id

    def end_span(self, span_id: str, status: str = "success", error_message: str = None):
        """Beendet einen Span."""
        if span_id not in self.active_spans:
            logger.warning(f"Trying to end non-existent span: {span_id}")
            return

        span = self.active_spans[span_id]
        span.end_time = datetime.utcnow()
        span.duration_ms = (span.end_time - span.start_time).total_seconds() * 1000
        span.status = status
        span.error_message = error_message

        # Entferne aus aktiven Spans
        del self.active_spans[span_id]

        # Setze Context zurück zu Parent
        if span.parent_span_id:
            context = trace_context.get()
            if context:
                context["span_id"] = span.parent_span_id
                context["parent_span_id"] = self._get_parent_of_span(span.parent_span_id, span.trace_id)
                trace_context.set(context)

        if self.export_to_console:
            logger.info(f"Span ended: {span_id}, Duration: {span.duration_ms:.2f}ms, Status: {status}")

    def _get_parent_of_span(self, span_id: str, trace_id: str) -> Optional[str]:
        """Findet Parent-Span-ID."""
        if trace_id in self.traces and span_id in self.traces[trace_id].spans:
            return self.traces[trace_id].spans[span_id].parent_span_id
        return None

    def add_event(self, span_id: str, name: str, attributes: Dict[str, Any] = None):
        """Fügt ein Event zu einem Span hinzu."""
        if span_id not in self.active_spans:
            # Versuche in beendeten Spans
            for trace in self.traces.values():
                if span_id in trace.spans:
                    trace.spans[span_id].events.append({
                        "name": name,
                        "timestamp": datetime.utcnow().isoformat(),
                        "attributes": attributes or {}
                    })
                    return
            logger.warning(f"Cannot add event to non-existent span: {span_id}")
            return

        self.active_spans[span_id].events.append({
            "name": name,
            "timestamp": datetime.utcnow().isoformat(),
            "attributes": attributes or {}
        })

    def add_attribute(self, span_id: str, key: str, value: Any):
        """Fügt ein Attribut zu einem Span hinzu."""
        if span_id not in self.active_spans:
            # Versuche in beendeten Spans
            for trace in self.traces.values():
                if span_id in trace.spans:
                    trace.spans[span_id].attributes[key] = value
                    return
            logger.warning(f"Cannot add attribute to non-existent span: {span_id}")
            return

        self.active_spans[span_id].attributes[key] = value

    def end_trace(self, trace_id: str):
        """Beendet einen Trace und alle seine Spans."""
        if trace_id not in self.traces:
            logger.warning(f"Trying to end non-existent trace: {trace_id}")
            return

        trace = self.traces[trace_id]
        trace.end_time = datetime.utcnow()

        # Beende alle aktiven Spans in diesem Trace
        span_ids_to_end = []
        for span_id, span in list(self.active_spans.items()):
            if span.trace_id == trace_id:
                span_ids_to_end.append(span_id)

        for span_id in span_ids_to_end:
            self.end_span(span_id, "success", "Trace ended")

        # Exportiere Trace wenn gewünscht
        if self.export_to_console:
            self._export_trace(trace)

    def _export_trace(self, trace: Trace):
        """Exportiert Trace zur Konsole (in Produktion zu Jaeger/Zipkin)."""
        try:
            trace_data = {
                "trace_id": trace.trace_id,
                "duration_ms": (trace.end_time - trace.start_time).total_seconds() * 1000 if trace.end_time else None,
                "span_count": len(trace.spans),
                "spans": []
            }

            for span_id, span in trace.spans.items():
                span_data = {
                    "span_id": span.span_id,
                    "parent_id": span.parent_span_id,
                    "name": span.name,
                    "duration_ms": span.duration_ms,
                    "status": span.status,
                    "attributes": span.attributes
                }
                trace_data["spans"].append(span_data)

            logger.info(f"Trace exported: {json.dumps(trace_data, default=str, indent=2)}")

        except Exception as e:
            logger.error(f"Error exporting trace: {e}")

    def get_trace(self, trace_id: str) -> Optional[Dict[str, Any]]:
        """Holt einen Trace."""
        if trace_id not in self.traces:
            return None

        trace = self.traces[trace_id]

        return {
            "trace_id": trace.trace_id,
            "start_time": trace.start_time.isoformat(),
            "end_time": trace.end_time.isoformat() if trace.end_time else None,
            "duration_ms": (trace.end_time - trace.start_time).total_seconds() * 1000
                          if trace.end_time else None,
            "span_count": len(trace.spans),
            "spans": [asdict(span) for span in trace.spans.values()],
            "metadata": trace.metadata
        }

    def get_current_context(self) -> Dict[str, Any]:
        """Gibt den aktuellen Trace-Kontext zurück."""
        context = trace_context.get()
        if context:
            return context.copy()
        return {}

