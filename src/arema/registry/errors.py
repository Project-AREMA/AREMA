"""Typed errors raised while composing the AREMA capability catalog."""


class CatalogError(Exception):
    """Base class for capability catalog failures."""


class CatalogValidationError(CatalogError, ValueError):
    """Base class for invalid catalog definitions."""


class InvalidCapabilityDescriptorError(CatalogValidationError):
    """Raised when a capability descriptor violates a scalar invariant."""


class DuplicateCapabilityError(CatalogValidationError):
    """Raised when a registry already contains a capability identifier."""


class UnresolvedCapabilityError(CatalogValidationError):
    """Raised when an agent references an unregistered capability."""


class CapabilityCycleError(CatalogValidationError):
    """Raised when sub-agent dependencies form a cycle."""


class InvalidRootError(CatalogValidationError):
    """Raised when the declared root agent is not registered."""


class UnreachableAgentError(CatalogValidationError):
    """Raised when a registered agent cannot be reached from the root."""


class InvalidToolDescriptorError(CatalogValidationError):
    """Raised when a tool descriptor has an invalid source or policy."""


class InvalidTransportError(CatalogValidationError):
    """Raised when an MCP transport has invalid connection settings."""


class MissingEnvironmentValueError(CatalogValidationError):
    """Raised when a capability requires a missing environment value."""


class CatalogFrozenError(CatalogError, RuntimeError):
    """Raised when a frozen catalog builder receives a mutation request."""
