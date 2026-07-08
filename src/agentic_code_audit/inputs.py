from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from .models import InputSource


GIT_URL_RE = re.compile(r"^(https://|http://|git@|ssh://).+\.git/?$")
GITHUB_SHORT_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class TargetResolver:
    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root.resolve()
        self.git_env = self._git_env()

    def resolve(self, target: str) -> InputSource:
        raw = target.strip()
        if not raw:
            raise ValueError("target is required")

        path = Path(raw)
        if not path.is_absolute():
            path = Path.cwd() / path
        path = path.resolve()
        if path.exists() and path.is_dir():
            return InputSource(original=raw, kind="local", local_path=str(path), workspace=str(path))

        if self._looks_like_repo(raw):
            return self._clone_or_update(raw)

        raise ValueError(f"Target directory does not exist and target is not a recognized Git repo: {raw}")

    def _looks_like_repo(self, value: str) -> bool:
        if GITHUB_SHORT_RE.match(value):
            return True
        if GIT_URL_RE.match(value):
            return True
        parsed = urlparse(value)
        return parsed.netloc.lower() in {"github.com", "www.github.com"} and bool(parsed.path.strip("/"))

    def _normalize_repo_url(self, value: str) -> str:
        if GITHUB_SHORT_RE.match(value):
            return f"https://github.com/{value}.git"
        if value.startswith("https://github.com/") and not value.endswith(".git"):
            return value.rstrip("/") + ".git"
        return value

    def _clone_or_update(self, value: str) -> InputSource:
        url = self._normalize_repo_url(value)
        if not shutil.which("git"):
            raise ValueError("git is required to audit remote repositories")

        repo_id = hashlib.sha1(url.encode("utf-8")).hexdigest()[:12]
        repo_dir = self.workspace_root / "repos" / repo_id
        repo_dir.parent.mkdir(parents=True, exist_ok=True)

        cloned = False
        if repo_dir.exists() and (repo_dir / ".git").exists():
            self._run_git(["git", "fetch", "--all", "--prune"], repo_dir)
            self._run_git(["git", "pull", "--ff-only"], repo_dir)
        else:
            if repo_dir.exists():
                shutil.rmtree(repo_dir)
            self._run_git(["git", "clone", "--depth", "1", url, str(repo_dir)], Path.cwd())
            cloned = True

        commit = self._run_git(["git", "rev-parse", "HEAD"], repo_dir).strip()
        return InputSource(
            original=value,
            kind="git",
            local_path=str(repo_dir.resolve()),
            workspace=str(repo_dir.parent.resolve()),
            cloned=cloned,
            commit=commit,
        )

    def _run_git(self, command: list[str], cwd: Path) -> str:
        proc = subprocess.run(
            command,
            cwd=str(cwd),
            text=True,
            capture_output=True,
            timeout=300,
            check=False,
            env=self.git_env,
        )
        if proc.returncode != 0:
            detail = proc.stderr.strip() or proc.stdout.strip()
            raise ValueError(f"git command failed: {' '.join(command)}\n{detail}")
        return proc.stdout

    def _git_env(self) -> dict[str, str]:
        env = os.environ.copy()
        for key, env_names in {
            "http.proxy": ("HTTP_PROXY", "http_proxy"),
            "https.proxy": ("HTTPS_PROXY", "https_proxy"),
        }.items():
            proxy = self._read_git_config(key)
            if proxy:
                for env_name in env_names:
                    env.setdefault(env_name, proxy)
        return env

    def _read_git_config(self, key: str) -> str:
        try:
            proc = subprocess.run(
                ["git", "config", "--get", key],
                cwd=str(Path.cwd()),
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return ""
        return proc.stdout.strip() if proc.returncode == 0 else ""
