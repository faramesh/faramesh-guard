"""
Bash/Shell command extractor.

Extracts rich context from shell commands for security analysis.
"""

import re
import shlex
from typing import Dict, Any, List, Set

from .base import (
    BaseExtractor,
    ExtractorResult,
    ExtractedTarget,
    RiskFactor,
)


class BashExtractor(BaseExtractor):
    """Extractor for bash/shell commands."""

    tool_patterns = ["bash", "shell", "exec", "run", "command", "terminal"]

    # Dangerous commands that require approval
    DANGEROUS_COMMANDS = {
        "rm": {"flags": ["-rf", "-fr", "--recursive"], "always_dangerous": False},
        "sudo": {"flags": [], "always_dangerous": True},
        "chmod": {"flags": ["777", "+x"], "always_dangerous": False},
        "chown": {"flags": [], "always_dangerous": True},
        "curl": {"flags": ["|", "-o"], "always_dangerous": False},
        "wget": {"flags": ["|", "-O"], "always_dangerous": False},
        "dd": {"flags": [], "always_dangerous": True},
        "mkfs": {"flags": [], "always_dangerous": True},
        "fdisk": {"flags": [], "always_dangerous": True},
        "shutdown": {"flags": [], "always_dangerous": True},
        "reboot": {"flags": [], "always_dangerous": True},
        "kill": {"flags": ["-9", "-KILL"], "always_dangerous": False},
        "pkill": {"flags": [], "always_dangerous": False},
        "eval": {"flags": [], "always_dangerous": True},
        "source": {"flags": [], "always_dangerous": False},
        ".": {"flags": [], "always_dangerous": False},  # source alias
    }

    # Commands that access sensitive data
    SENSITIVE_COMMANDS = {
        "cat",
        "less",
        "more",
        "head",
        "tail",
        "grep",
        "awk",
        "sed",
        "vim",
        "nano",
        "code",
        "open",
    }

    # Network commands
    NETWORK_COMMANDS = {
        "curl",
        "wget",
        "nc",
        "netcat",
        "ssh",
        "scp",
        "rsync",
        "ftp",
        "sftp",
        "telnet",
        "ping",
        "traceroute",
        "nmap",
        "dig",
        "nslookup",
        "host",
    }

    # Installation commands
    INSTALL_COMMANDS = {
        "pip",
        "npm",
        "yarn",
        "pnpm",
        "brew",
        "apt",
        "apt-get",
        "yum",
        "dnf",
        "pacman",
        "gem",
        "cargo",
        "go",
    }

    def extract(self, tool_name: str, args: Dict[str, Any]) -> ExtractorResult:
        """Extract context from shell command."""

        # Get command string
        command = args.get("command", args.get("cmd", ""))
        if not command:
            return ExtractorResult(
                tool_name=tool_name,
                operation="unknown",
                authority_domain="exec",
                human_summary="Empty command",
            )

        # Parse command
        parsed = self._parse_command(command)

        # Determine operation from primary command
        primary_cmd = parsed.get("primary_command", "")
        operation = self._classify_operation(primary_cmd, parsed)

        # Extract targets
        targets = self._extract_targets(parsed)

        # Assess risk factors
        risk_factors, risk_score = self._assess_risks(command, parsed)

        # Determine blast radius
        blast_radius = self._determine_blast_radius(parsed, risk_factors)

        # Determine reversibility
        reversibility = self._determine_reversibility(primary_cmd, parsed)

        # Generate human summary
        human_summary = self._generate_summary(command, parsed, risk_factors)

        # Determine if approval needed
        requires_approval, approval_reason = self._needs_approval(
            command, parsed, risk_factors
        )

        return ExtractorResult(
            tool_name=tool_name,
            operation=operation,
            authority_domain="exec",
            targets=targets,
            risk_factors=risk_factors,
            risk_score=risk_score,
            normalized_args={"command": command, "parsed": parsed},
            blast_radius=blast_radius,
            reversibility=reversibility,
            human_summary=human_summary,
            requires_approval=requires_approval,
            approval_reason=approval_reason,
        )

    def _parse_command(self, command: str) -> Dict[str, Any]:
        """Parse command into structured representation."""
        result = {
            "raw": command,
            "primary_command": "",
            "subcommands": [],
            "flags": [],
            "args": [],
            "files": [],
            "urls": [],
            "pipes": [],
            "redirects": [],
            "env_vars": [],
            "has_shell_chars": False,
        }

        # Check for shell metacharacters
        shell_chars = [";", "&&", "||", "|", "`", "$(", "${", ">", "<", ">>"]
        for char in shell_chars:
            if char in command:
                result["has_shell_chars"] = True
                break

        # Split by pipes
        if "|" in command:
            result["pipes"] = [cmd.strip() for cmd in command.split("|")]

        # Try to parse with shlex
        try:
            tokens = shlex.split(command)
        except ValueError:
            # Fallback to simple split
            tokens = command.split()

        if not tokens:
            return result

        # First token is primary command
        result["primary_command"] = tokens[0]

        # Parse remaining tokens
        for token in tokens[1:]:
            if token.startswith("-"):
                result["flags"].append(token)
            elif token.startswith("$"):
                result["env_vars"].append(token)
            elif self._looks_like_url(token):
                result["urls"].append(token)
            elif self._looks_like_file(token):
                result["files"].append(token)
            else:
                result["args"].append(token)

        # Check for redirects
        redirect_patterns = [">", ">>", "<", "2>", "2>>", "&>"]
        for pattern in redirect_patterns:
            if pattern in command:
                result["redirects"].append(pattern)

        return result

    def _looks_like_url(self, token: str) -> bool:
        """Check if token looks like a URL."""
        return token.startswith(("http://", "https://", "ftp://", "file://"))

    def _looks_like_file(self, token: str) -> bool:
        """Check if token looks like a file path."""
        # Absolute paths
        if token.startswith("/") or token.startswith("~"):
            return True
        # Relative paths with directory
        if "/" in token and not self._looks_like_url(token):
            return True
        # Common file extensions
        extensions = [
            ".txt",
            ".py",
            ".js",
            ".ts",
            ".json",
            ".yaml",
            ".yml",
            ".md",
            ".sh",
            ".bash",
            ".zsh",
            ".env",
            ".conf",
            ".cfg",
        ]
        return any(token.endswith(ext) for ext in extensions)

    def _classify_operation(self, primary_cmd: str, parsed: Dict[str, Any]) -> str:
        """Classify the operation type."""
        cmd = primary_cmd.lower()

        if cmd in ("rm", "rmdir", "unlink"):
            return "delete"
        elif cmd in ("cp", "mv", "rsync"):
            return "copy" if cmd == "cp" else "move"
        elif cmd in ("mkdir", "touch", "mktemp"):
            return "create"
        elif cmd in ("cat", "less", "more", "head", "tail", "grep"):
            return "read"
        elif cmd in ("echo", "printf", "tee"):
            return "write" if parsed.get("redirects") else "print"
        elif cmd in ("chmod", "chown", "chgrp"):
            return "permission"
        elif cmd in self.NETWORK_COMMANDS:
            return "network"
        elif cmd in self.INSTALL_COMMANDS:
            return "install"
        elif cmd in ("cd", "pwd", "ls", "dir", "find", "locate"):
            return "navigate"
        elif cmd in ("git",):
            # Git subcommand classification
            args = parsed.get("args", [])
            if args:
                subcmd = args[0]
                if subcmd in ("push", "force-push"):
                    return "git_push"
                elif subcmd in ("reset", "rebase"):
                    return "git_modify_history"
                elif subcmd in ("commit", "add", "merge"):
                    return "git_commit"
                elif subcmd in ("clone", "pull", "fetch"):
                    return "git_fetch"
            return "git"
        elif cmd in ("docker", "podman"):
            return "container"
        elif cmd in ("kubectl", "k9s", "helm"):
            return "kubernetes"
        elif cmd == "sudo":
            return "privileged"
        else:
            return "execute"

    def _extract_targets(self, parsed: Dict[str, Any]) -> List[ExtractedTarget]:
        """Extract targets from parsed command."""
        targets = []

        # Files
        for file_path in parsed.get("files", []):
            normalized = self.normalize_path(file_path)
            targets.append(
                ExtractedTarget(
                    kind="file",
                    value=file_path,
                    normalized=normalized,
                    sensitive=self.is_sensitive_path(normalized),
                    internal=True,
                    metadata={
                        "system_path": self.is_system_path(normalized),
                    },
                )
            )

        # URLs
        for url in parsed.get("urls", []):
            # Parse URL to extract host
            import urllib.parse

            parsed_url = urllib.parse.urlparse(url)
            targets.append(
                ExtractedTarget(
                    kind="url",
                    value=url,
                    normalized=url,
                    sensitive=self._is_sensitive_url(url),
                    internal=self._is_internal_url(parsed_url.netloc),
                    metadata={
                        "host": parsed_url.netloc,
                        "scheme": parsed_url.scheme,
                        "path": parsed_url.path,
                    },
                )
            )

        return targets

    def _is_sensitive_url(self, url: str) -> bool:
        """Check if URL might contain sensitive data."""
        sensitive_patterns = [
            "password",
            "token",
            "key",
            "secret",
            "auth",
            "credential",
            "api_key",
            "apikey",
        ]
        url_lower = url.lower()
        return any(pattern in url_lower for pattern in sensitive_patterns)

    def _is_internal_url(self, host: str) -> bool:
        """Check if host is internal."""
        internal_patterns = [
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "192.168.",
            "10.",
            "172.16.",
            "172.17.",
            "172.18.",
            ".local",
            ".internal",
            ".corp",
        ]
        host_lower = host.lower()
        return any(pattern in host_lower for pattern in internal_patterns)

    def _assess_risks(
        self, command: str, parsed: Dict[str, Any]
    ) -> tuple[List[RiskFactor], int]:
        """Assess risk factors and compute score."""
        factors = []
        score = 0

        primary = parsed.get("primary_command", "").lower()
        flags = parsed.get("flags", [])

        # Shell injection
        if parsed.get("has_shell_chars") and any(
            char in command for char in ["`", "$(", "${"]
        ):
            factors.append(RiskFactor.SHELL_INJECTION)
            score += 30

        # Privilege escalation
        if primary == "sudo" or "sudo" in command:
            factors.append(RiskFactor.PRIVILEGE_ESCALATION)
            score += 40

        # Remote code execution
        if any(
            pattern in command.lower()
            for pattern in ["curl", "wget", "bash", "sh", "python", "node"]
            if "|" in command and pattern in command
        ):
            factors.append(RiskFactor.REMOTE_CODE)
            score += 50

        # System modification
        if primary in ("chmod", "chown", "chgrp"):
            factors.append(RiskFactor.SYSTEM_MODIFICATION)
            score += 20

        # Path traversal
        if ".." in command:
            factors.append(RiskFactor.PATH_TRAVERSAL)
            score += 15

        # Sensitive paths
        for target in self._extract_targets(parsed):
            if target.sensitive:
                factors.append(RiskFactor.SENSITIVE_PATH)
                score += 25
                break

        # Permission changes
        if primary == "chmod":
            if "777" in command or "+x" in command:
                factors.append(RiskFactor.PERMISSION_CHANGE)
                score += 25

        # Recursive delete
        if primary == "rm" and any(
            f in flags for f in ["-r", "-rf", "-fr", "--recursive"]
        ):
            factors.append(RiskFactor.RECURSIVE_DELETE)
            score += 35

        # External network
        for target in self._extract_targets(parsed):
            if target.kind == "url" and not target.internal:
                factors.append(RiskFactor.EXTERNAL_NETWORK)
                score += 20
                break

        # Credential exposure
        if any(
            pattern in command.lower()
            for pattern in ["password", "token", "secret", "key"]
        ):
            factors.append(RiskFactor.CREDENTIAL_EXPOSURE)
            score += 30

        # Cap at 100
        score = min(score, 100)

        return factors, score

    def _determine_blast_radius(
        self, parsed: Dict[str, Any], risk_factors: List[RiskFactor]
    ) -> str:
        """Determine the blast radius of the command."""
        primary = parsed.get("primary_command", "").lower()

        # Network commands affect network
        if primary in self.NETWORK_COMMANDS:
            return "network"

        # Privileged commands affect system
        if RiskFactor.PRIVILEGE_ESCALATION in risk_factors:
            return "system"

        # Recursive delete affects workspace
        if RiskFactor.RECURSIVE_DELETE in risk_factors:
            return "workspace"

        # System paths affect system
        for target in self._extract_targets(parsed):
            if target.metadata.get("system_path"):
                return "system"

        return "user"

    def _determine_reversibility(self, primary_cmd: str, parsed: Dict[str, Any]) -> str:
        """Determine if the action is reversible."""
        cmd = primary_cmd.lower()
        flags = parsed.get("flags", [])

        # Irreversible operations
        if cmd in ("rm", "rmdir", "unlink"):
            if any(f in flags for f in ["-r", "-rf", "-fr", "--recursive"]):
                return "irreversible"
            return "irreversible"  # Even single file delete

        if cmd in ("dd", "mkfs", "fdisk", "shred"):
            return "irreversible"

        # Partially reversible
        if cmd in ("mv", "chmod", "chown"):
            return "partial"

        if cmd == "git":
            args = parsed.get("args", [])
            if args and args[0] in ("push", "force-push", "reset", "rebase"):
                return "partial"

        return "reversible"

    def _generate_summary(
        self,
        command: str,
        parsed: Dict[str, Any],
        risk_factors: List[RiskFactor],
    ) -> str:
        """Generate human-readable summary."""
        primary = parsed.get("primary_command", "")

        if not primary:
            return "Empty command"

        # Truncate long commands
        cmd_display = command if len(command) < 60 else command[:57] + "..."

        # Build summary
        parts = [f"Execute: {cmd_display}"]

        if risk_factors:
            risks = ", ".join(rf.value for rf in risk_factors[:3])
            parts.append(f"Risks: {risks}")

        return " | ".join(parts)

    def _needs_approval(
        self,
        command: str,
        parsed: Dict[str, Any],
        risk_factors: List[RiskFactor],
    ) -> tuple[bool, str | None]:
        """Determine if command needs human approval."""
        primary = parsed.get("primary_command", "").lower()
        flags = parsed.get("flags", [])

        # Check dangerous commands
        if primary in self.DANGEROUS_COMMANDS:
            cfg = self.DANGEROUS_COMMANDS[primary]
            if cfg["always_dangerous"]:
                return True, f"Dangerous command: {primary}"

            # Check specific dangerous flags
            for flag in cfg["flags"]:
                if flag in command:
                    return True, f"Dangerous flag in {primary}: {flag}"

        # Sensitive path access
        if RiskFactor.SENSITIVE_PATH in risk_factors:
            # Find the sensitive target
            for target in self._extract_targets(parsed):
                if target.sensitive:
                    return True, f"Sensitive file access: {target.value}"

        # High risk score
        risk_score = sum(
            (
                30
                if rf == RiskFactor.REMOTE_CODE
                else (
                    25
                    if rf
                    in (RiskFactor.PRIVILEGE_ESCALATION, RiskFactor.RECURSIVE_DELETE)
                    else 15
                )
            )
            for rf in risk_factors
        )

        if risk_score >= 50:
            return True, f"High risk score: {risk_score}"

        # Recursive delete
        if primary == "rm" and any(f in flags for f in ["-rf", "-fr", "-r"]):
            return True, "Recursive file deletion"

        # Curl/wget piped to shell
        if (
            primary in ("curl", "wget")
            and "|" in command
            and any(sh in command for sh in ["sh", "bash", "zsh"])
        ):
            return True, "Remote code execution pattern"

        return False, None
