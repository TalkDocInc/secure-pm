from rich.console import Console
from rich.markdown import Markdown
from rich import print as rprint
import re
import os

console = Console()

class RichLogger:
    def __init__(self):
        self.console = Console()

    def _parse_markup(self, text):
        # Simple parser for common rich markup since Markdown may not handle all tags perfectly
        # Replace <color>text</color> with [color]text[/color]
        def repl_color(match):
            color = match.group(1)
            text = match.group(2)
            return f"[{color}]{text}[/{color}]"
        
        text = re.sub(r'<([a-z]+)>(.*?)</\1>', repl_color, text, flags=re.DOTALL)
        # Handle self-closing like <bold> but assume paired
        text = re.sub(r'<bold>(.*?)</bold>', r'[\1[/bold>\g<1>]', text, flags=re.DOTALL)
        text = text.replace('<', '<').replace('>', '>')
        return text

    def info(self, text):
        formatted = self._parse_markup(str(text))
        self.console.print(formatted, style="bold blue")

    def error(self, text):
        formatted = self._parse_markup(str(text))
        self.console.print(formatted, style="bold red")

    def warning(self, text):
        formatted = self._parse_markup(str(text))
        self.console.print(formatted, style="bold yellow")

logger = RichLogger()

def configure_logging():
    """Configure logging setup. Stub for now."""
    os.environ.setdefault('RICH_TRACEBACK', '1')
    pass

