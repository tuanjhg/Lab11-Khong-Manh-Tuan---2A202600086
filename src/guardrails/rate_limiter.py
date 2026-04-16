"""
Lab 11 — Rate Limiter Plugin
Prevents abuse by limiting the number of requests per user in a time window.
"""
import time
from collections import defaultdict, deque
from typing import Optional

from google.genai import types
from google.adk.plugins import base_plugin
from google.adk.agents.invocation_context import InvocationContext


class RateLimitPlugin(base_plugin.BasePlugin):
    """Plugin that enforces rate limiting per user.
    
    Purpose: Prevent abuse and DoS attacks by limiting request frequency.
    Uses a sliding window to track requests within a time window.
    """

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        """Initialize rate limiter.
        
        Args:
            max_requests: Maximum requests allowed per user in the time window
            window_seconds: Time window in seconds
        """
        super().__init__(name="rate_limiter")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.user_windows = defaultdict(deque)  # deque of (timestamp, allowed)
        self.blocked_count = 0
        self.total_count = 0

    def _block_response(self, wait_seconds: float) -> types.Content:
        """Create a rate limit block response."""
        message = f"Rate limit exceeded. Please wait {wait_seconds:.1f} seconds before trying again."
        return types.Content(
            role="model",
            parts=[types.Part.from_text(text=message)],
        )

    async def on_user_message_callback(
        self,
        *,
        invocation_context: Optional[InvocationContext],
        user_message: types.Content,
    ) -> Optional[types.Content]:
        """Check if user has exceeded rate limit.
        
        Purpose: Block requests from users who are sending too many messages
        in a short time window.
        
        Returns:
            None if under limit (allow),
            types.Content if over limit (block with wait time)
        """
        self.total_count += 1

        # Get user ID from context
        user_id = "anonymous"
        if invocation_context and hasattr(invocation_context, "user_id"):
            user_id = invocation_context.user_id

        now = time.time()
        window = self.user_windows[user_id]

        # Remove timestamps outside the window (sliding window)
        while window and window[0][0] < now - self.window_seconds:
            window.popleft()

        # Check if user has exceeded limit
        if len(window) >= self.max_requests:
            # Calculate wait time until oldest request falls out of window
            oldest_time = window[0][0]
            wait_time = (oldest_time + self.window_seconds) - now
            self.blocked_count += 1
            return self._block_response(wait_time)

        # Add current request to window
        window.append((now, True))
        return None  # Allow request

    def get_stats(self) -> dict:
        """Get rate limiter statistics."""
        return {
            "total_requests": self.total_count,
            "blocked_requests": self.blocked_count,
            "block_rate": self.blocked_count / self.total_count if self.total_count > 0 else 0,
            "active_users": len(self.user_windows),
        }
