import logging
from rich.logging import RichHandler
from rich.console import Console

# Universal Console instance
console = Console()

def setup_logger(name="HunterLoop"):
    """
    Configures a Rich logger for the pipeline.
    """
    logging.basicConfig(
        level="INFO",
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True, markup=True)]
    )
    
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    return logger

# Singleton Logger
log = setup_logger()
