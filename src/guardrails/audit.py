"""
Lab 11 — Audit Log & Monitoring
Tracks all interactions and fires alerts when thresholds are exceeded.
"""
import json
import time
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Optional, List

from google.genai import types
from google.adk.plugins import base_plugin


@dataclass
class AuditEntry:
    """A single audit log entry."""
    timestamp: str
    user_id: str
    input_text: str
    output_text: str
    blocked_by: Optional[str] = None
    latency_ms: float = 0.0
    model: str = "gemini-2.5-flash-lite"


class AuditLogPlugin(base_plugin.BasePlugin):
    """Plugin that logs all interactions for monitoring and compliance.
    
    Purpose: Provide a complete audit trail of all requests and responses,
    including which safety layers triggered. Essential for security analysis
    and compliance auditing.
    """

    def __init__(self):
        """Initialize audit logger."""
        super().__init__(name="audit_log")
        self.logs: List[AuditEntry] = []
        self.current_request = {}  # Track in-progress request

    async def on_user_message_callback(
        self,
        *,
        invocation_context,
        user_message: types.Content,
    ) -> Optional[types.Content]:
        """Log incoming user message."""
        # Extract user ID and message text
        user_id = "anonymous"
        if invocation_context and hasattr(invocation_context, "user_id"):
            user_id = invocation_context.user_id

        text = ""
        if user_message and user_message.parts:
            for part in user_message.parts:
                if hasattr(part, "text") and part.text:
                    text += part.text

        # Store request in-progress data
        self.current_request = {
            "user_id": user_id,
            "input_text": text,
            "timestamp": datetime.utcnow().isoformat(),
            "start_time": time.time(),
        }

        # Don't modify the message
        return None

    async def after_model_callback(
        self,
        *,
        callback_context,
        llm_response,
    ):
        """Log outgoing LLM response."""
        # Extract response text
        text = ""
        if hasattr(llm_response, "content") and llm_response.content:
            for part in llm_response.content.parts:
                if hasattr(part, "text") and part.text:
                    text += part.text

        # Calculate latency
        latency_ms = (time.time() - self.current_request.get("start_time", 0)) * 1000

        # Create audit entry
        entry = AuditEntry(
            timestamp=self.current_request.get("timestamp", 
                                             datetime.utcnow().isoformat()),
            user_id=self.current_request.get("user_id", "anonymous"),
            input_text=self.current_request.get("input_text", ""),
            output_text=text,
            latency_ms=latency_ms,
        )
        self.logs.append(entry)
        self.current_request = {}

        # Don't modify the response
        return llm_response

    def export_json(self, filepath: str = "audit_log.json") -> None:
        """Export audit log to JSON file.
        
        Args:
            filepath: Path to write the JSON file
        """
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(
                [asdict(entry) for entry in self.logs],
                f,
                indent=2,
                default=str,
            )
        print(f"Audit log exported to {filepath} ({len(self.logs)} entries)")

    def get_stats(self) -> dict:
        """Get audit log statistics."""
        if not self.logs:
            return {
                "total_entries": 0,
                "unique_users": 0,
                "avg_latency_ms": 0,
                "min_latency_ms": 0,
                "max_latency_ms": 0,
            }

        latencies = [entry.latency_ms for entry in self.logs]
        unique_users = len(set(entry.user_id for entry in self.logs))

        return {
            "total_entries": len(self.logs),
            "unique_users": unique_users,
            "avg_latency_ms": sum(latencies) / len(latencies),
            "min_latency_ms": min(latencies),
            "max_latency_ms": max(latencies),
        }


class MonitoringAlert:
    """Monitor guardrail statistics and fire alerts."""

    def __init__(self, plugins: list):
        """Initialize monitoring with a list of plugins.
        
        Args:
            plugins: List of guardrail plugins to monitor
        """
        self.plugins = plugins
        self.thresholds = {
            "block_rate": 0.3,  # Alert if >30% of requests blocked
            "rate_limit_block_rate": 0.1,  # Alert if >10% rate-limited
            "avg_latency_ms": 2000,  # Alert if average latency > 2s
        }

    def check_metrics(self) -> dict:
        """Check plugin metrics against thresholds.
        
        Returns:
            dict with alerts if thresholds exceeded
        """
        alerts = []

        for plugin in self.plugins:
            if not hasattr(plugin, "get_stats"):
                continue

            stats = plugin.get_stats()
            plugin_name = plugin.name if hasattr(plugin, "name") else "unknown"

            # Check for high block rate
            if "block_rate" in stats and stats["block_rate"] > self.thresholds["block_rate"]:
                alerts.append(
                    f"⚠️  {plugin_name}: Block rate {stats['block_rate']:.1%} "
                    f"exceeds threshold {self.thresholds['block_rate']:.1%}"
                )

            # Check for high average latency
            if "avg_latency_ms" in stats and stats["avg_latency_ms"] > self.thresholds["avg_latency_ms"]:
                alerts.append(
                    f"⚠️  {plugin_name}: Average latency {stats['avg_latency_ms']:.0f}ms "
                    f"exceeds threshold {self.thresholds['avg_latency_ms']:.0f}ms"
                )

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "alert_count": len(alerts),
            "alerts": alerts,
        }

    def print_report(self) -> None:
        """Print a formatted monitoring report."""
        print("\n" + "=" * 70)
        print("SECURITY MONITORING REPORT")
        print("=" * 70)

        for plugin in self.plugins:
            if not hasattr(plugin, "get_stats"):
                continue

            stats = plugin.get_stats()
            plugin_name = plugin.name if hasattr(plugin, "name") else "unknown"
            print(f"\n{plugin_name.upper()}:")
            for key, value in stats.items():
                if isinstance(value, float):
                    if "rate" in key:
                        print(f"  {key}: {value:.1%}")
                    else:
                        print(f"  {key}: {value:.2f}")
                else:
                    print(f"  {key}: {value}")

        # Print alerts
        alert_result = self.check_metrics()
        if alert_result["alerts"]:
            print("\n" + "-" * 70)
            print("ALERTS:")
            for alert in alert_result["alerts"]:
                print(f"  {alert}")
        else:
            print("\n✓ No alerts - all metrics within acceptable ranges")

        print("=" * 70 + "\n")
