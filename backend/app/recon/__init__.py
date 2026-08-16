"""Reconnaissance modules.

Every module that performs network I/O accepts a :class:`ScopeValidator` and a
:class:`SafeHttpClient`. The client is the single chokepoint that guarantees
no request leaves the authorized scope.
"""
