"""
Custom exceptions for the AppSecAI platform.
"""

class AppSecAIError(Exception):
    """Base exception for all AppSecAI errors."""
    pass

class OrchestrationError(AppSecAIError):
    """Base exception for orchestration errors."""
    pass

class DockerNotFoundError(OrchestrationError):
    """Raised when Docker is not found on the system."""
    pass

class DockerExecutionError(OrchestrationError):
    """Raised when a Docker command fails."""
    pass

class SonarQubeError(OrchestrationError):
    """Base exception for SonarQube-related errors."""
    pass

class SonarQubeBootTimeout(SonarQubeError):
    """Raised when SonarQube fails to boot within the expected time."""
    pass

class SonarQubeAPIError(SonarQubeError):
    """Raised when a SonarQube API call fails."""
    pass
