"""AREMA's welcome/router agent.

The greeter is the single top-level entry users talk to. It owns no tools and
performs no analysis itself: it greets the user and delegates each request to
the appropriate domain agent (registered as ADK sub-agents). Today that is
``malware_analyst``; future domains (e.g. vulnerability_researcher) are added
by appending their root agent to ``DOMAIN_ROOTS`` below.
"""
