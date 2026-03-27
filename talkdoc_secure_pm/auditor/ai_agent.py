import os
from openai import OpenAI
from rich.console import Console

console = Console()

class AIAuditor:
    def __init__(self):
        self.provider = os.getenv("AI_PROVIDER", "grok").lower()
        self.client = None
        self.model = None
        self.cache = {}  # Simple in-memory cache: package_name -> result

        if self.provider == "grok":
            self.api_key = os.getenv("XAI_API_KEY")
            if self.api_key:
                # Grok API is OpenAI compatible
                self.client = OpenAI(api_key=self.api_key, base_url="https://api.x.ai/v1")
                self.model = os.getenv("AI_MODEL", os.getenv("GROK_MODEL", "grok-4-1-fast-reasoning"))
        elif self.provider == "openai":
            self.api_key = os.getenv("OPENAI_API_KEY")
            if self.api_key:
                self.client = OpenAI(api_key=self.api_key)
                self.model = os.getenv("AI_MODEL", "gpt-5-mini")
        elif self.provider == "gemini":
            self.api_key = os.getenv("GEMINI_API_KEY")
            if self.api_key:
                # Assuming usage of Gemini's OpenAI-compatible endpoint
                self.client = OpenAI(api_key=self.api_key, base_url="https://generativelanguage.googleapis.com/v1beta/openai/")
                self.model = os.getenv("AI_MODEL", "gemini-3.1-flash-lite-preview")
        elif self.provider == "ollama":
            self.model = os.getenv("AI_MODEL", os.getenv("OLLAMA_MODEL", "llama3"))
            ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
            ollama_api_key = os.getenv("OLLAMA_API_KEY", "ollama")
            # OpenAI client works with local Ollama 
            self.client = OpenAI(base_url=ollama_base_url, api_key=ollama_api_key)
            
        if not self.client:
            console.print(f"[yellow]WARNING: Provider '{self.provider}' not configured properly. Auditing will be simulated.[/yellow]")

    def audit_package_source(self, package_name: str, extract_dir: str) -> bool:
        """
        Reads critical files from the extracted directory and asks the LLM to audit them.
        Returns True if approved, False if malicious.
        """
        if package_name in self.cache:
            console.print(f"[cyan]Cache hit for {package_name}[/cyan]")
            return self.cache[package_name]

        if not self.client or not self.model:
            console.print(f"[yellow]Simulating AI approval for {package_name} for testing purposes.[/yellow]")
            self.cache[package_name] = True
            return True

        # Gather critical files (e.g. setup.py, package.json, Cargo.toml, install scripts)
        critical_extensions = ['.py', '.js', '.sh', '.rs']
        code_snippets = []
        
        for root, dirs, files in os.walk(extract_dir):
            for file in files:
                if any(file.endswith(ext) for ext in critical_extensions) or file in ['setup.py', 'package.json', 'Cargo.toml', 'build.rs']:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            code_snippets.append(f"File: {file}\n```\n{content}\n```")
                    except Exception:
                        pass
        
        combined_code = "\n\n".join(code_snippets[:5])  # limit to avoid token overflow

        prompt = f"""
You are a top-tier security researcher and AI agent auditing the source code of a package named '{package_name}' before it is installed.
Look carefully for any indicators of supply chain attacks, such as:
- Exfiltrating environment variables or keys
- Obfuscated code execution (eval, base64 exec)
- Suspicious network requests to unknown domains during install time
- Remote access trojans / keyloggers

Here is the extracted package code (or the most relevant parts):
{combined_code}

Based on this code, does it look malicious?
Please respond with exactly one line either:
APPROVED
or
REJECTED: <reason>
"""
        console.print(f"[cyan]Sending source code of {package_name} to {self.model} ({self.provider}) for auditing...[/cyan]")
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a strict code security auditor. Ensure no malicious payload or hidden eval."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.0
            )
            content = response.choices[0].message.content
            decision = content.strip() if content else "REJECTED: No response"
            is_approved = decision.startswith("APPROVED")
            if is_approved:
                console.print(f"[bold green]AI Audit Passed for {package_name}[/bold green]")
            else:
                console.print(f"[bold red]AI Audit Failed for {package_name}: {decision}[/bold red]")
            self.cache[package_name] = is_approved
            return is_approved
        except Exception as e:
            console.print(f"[bold red]AI API error: {e}[/bold red]")
            self.cache[package_name] = False
            return False
