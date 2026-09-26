class DomainException(Exception):
    """Base exception for everything happening in the repository core business block."""
    pass

class InvalidGitRepositoryException(DomainException):
    """Raised when repository targets could not be fetched or are severely corrupt."""
    pass

class CodeParsingException(DomainException):
    """Raised when AST parses crash on syntax errors or unsupported extensions."""
    pass

class DuplicateRepositoryException(DomainException):
    """Raised when trying to import a repository URI already claimed in database limits."""
    pass
