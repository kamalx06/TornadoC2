"""Exception taxonomy.

Every layer in the stack — providers, dispatcher, tools, console,
MCP server — raises or catches from this taxonomy. The AI console
maps them to different UX; the MCP server maps them to different
error codes; the dispatcher uses them to decide whether to audit.
"""


class McpError(Exception):
    """Base. Carries a stable `code` for the wire and a `hint` the
    operator sees on the terminal."""
    code = 'mcp_error'

    def __init__(self, message, *, hint='', audit_id=None):
        super().__init__(message)
        self.hint = hint
        self.audit_id = audit_id


# ---- Client-facing ---------------------------------------------------

class CapabilityError(McpError):
    """Operator role lacks the capability a tool requires."""
    code = 'capability_denied'


class AllowlistError(McpError):
    """Verb or BOF not in the operator's local allowlist."""
    code = 'allowlist_denied'


class ApprovalError(McpError):
    """T3 tool called without operator approval (or from an
    external MCP client, where T3 is not exposed)."""
    code = 'approval_required'


class ValidationError(McpError):
    """Tool arguments failed schema or semantic validation."""
    code = 'invalid_arguments'


class NotFoundError(McpError):
    code = 'not_found'


# ---- Server-side (transport, auth) ----------------------------------

class TransportError(McpError):
    """REST call failed — network, TLS, session. Retryable in
    principle, but the console does not auto-retry."""
    code = 'transport_error'


class ServerError(McpError):
    """Team server returned 4xx/5xx with an error body."""
    code = 'server_error'


# ---- Provider-side ---------------------------------------------------

class ProviderError(McpError):
    """Provider rejected the request — auth, quota, upstream error.
    Retried once on 429/5xx in the console loop."""
    code = 'provider_error'


class ProviderNotConfiguredError(ProviderError):
    code = 'provider_not_configured'


# ---- Console ---------------------------------------------------------

class ConsoleAborted(McpError):
    """Operator typed Ctrl+C during a turn. Loop returns to prompt."""
    code = 'aborted'


class ContextOverflowError(McpError):
    """Conversation exceeded the context window even after
    compaction. Caller should start a new session."""
    code = 'context_overflow'