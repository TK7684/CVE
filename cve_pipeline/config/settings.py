from pathlib import Path
from typing import ClassVar, Dict, List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator

class Settings(BaseSettings):
    """
    Application Settings using Pydantic for validation.
    """
    # Paths (Computed after init)
    BASE_DIR: Path = Path(__file__).resolve().parent.parent
    DATA_DIR: Path = Field(default_factory=lambda: Path(__file__).resolve().parent.parent / "data")
    CONFIG_DIR: Path = Field(default_factory=lambda: Path(__file__).resolve().parent.parent / "config")
    SCOPE_FILE: Path = Field(default_factory=lambda: Path(__file__).resolve().parent.parent / "config" / "scope_rules.json")

    # API Keys & Strings
    GEMINI_API_KEY: str = Field(default="", description="API Key for Gemini")
    DISCORD_WEBHOOK_URL: str = Field(default="", description="Discord Webhook URL")
    USER_AGENT: str = "Mozilla/5.0 (Security-Pipeline/1.0)"

    # Pipeline Control
    GLOBAL_RATE_LIMIT: int = Field(default=150, ge=1, le=1000)
    MAX_THREADS: int = Field(default=10, ge=1, le=50)
    SUBPROCESS_TIMEOUT: int = Field(default=300, ge=10)
    
    # Safety
    ENABLE_BRUTEFORCE: bool = False

    # Configuration for Pydantic Settings
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True
    )
    
    @field_validator("GEMINI_API_KEY")
    @classmethod
    def validate_api_key(cls, v: str) -> str:
        if v and not v.startswith("AIza"): 
             # Just a weak check, or logging warning could go here if we had logging setup before settings
             pass
        return v

    def load_scope(self) -> Dict[str, List[str]]:
        """Loads scope rules from JSON file."""
        import json
        if not self.SCOPE_FILE.exists():
             return {"allowed_domains": [], "excluded_domains": []}
        try:
            with open(self.SCOPE_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            # We can't use global logger here as it likely depends on settings
            print(f"Error loading scope file: {e}") 
            return {"allowed_domains": [], "excluded_domains": []}

    def create_dirs(self):
        """Ensures critical directories exist."""
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.CONFIG_DIR.mkdir(parents=True, exist_ok=True)

# Instantiate and setup
settings = Settings()
settings.create_dirs()
