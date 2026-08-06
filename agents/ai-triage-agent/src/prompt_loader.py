from pathlib import Path

PROMPT_FILE = Path(__file__).parent.parent / "prompts" / "triage_prompt.txt"


def load_prompt_template() -> str:
    if not PROMPT_FILE.exists():
        raise FileNotFoundError(f"Prompt file not found: {PROMPT_FILE}")

    return PROMPT_FILE.read_text(encoding="utf-8")
