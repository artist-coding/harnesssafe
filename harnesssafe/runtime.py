from __future__ import annotations
import importlib.metadata
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from .common import ROOT, ExperimentError, file_hash, read_json, write_json
from .registry import ADAPTERS
from .config import input_inventory
from .config import HARNESS_ENV

def powershell() -> str:
    executable = shutil.which("pwsh")
    if not executable:
        raise ExperimentError("PowerShell 7 (pwsh) is required for managed Windows adapters")
    return executable

def resolve_executable(cfg: dict) -> Path:
    requested = cfg["executable"]
    found = shutil.which(requested)
    path = Path(found or requested).expanduser().resolve()
    if not path.is_file():
        raise ExperimentError(f"CLI executable not found: {requested}")
    return path

def probe(executable: Path, kind: str = "version", root: Path = ROOT, env: dict | None = None) -> str:
    if os.name == "nt":
        args = [powershell(), "-NoProfile", "-NonInteractive", "-File",
                str(root / "infra/harnesssafe_probe.ps1"), "-Executable", str(executable), "-Probe", kind]
    else:
        args = [str(executable)] + (["exec", "--help"] if kind == "exec-help" else ["--help"] if kind == "help" else ["--version"])
    result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30, env=env)
    if result.returncode:
        raise ExperimentError(f"CLI {kind} probe failed (exit {result.returncode})")
    text = result.stdout.strip()
    if not text:
        raise ExperimentError(f"CLI {kind} probe returned no output")
    return text

def validate_dependency_versions(packages: dict[str, str], requirements: Path) -> None:
    # The frozen fixture requirements use simple inclusive-lower/exclusive-upper bounds.
    def numeric(value: str) -> tuple[int, ...]:
        match = re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", value)
        if not match:
            raise ExperimentError(f"Non-release dependency version is not reproducibly supported: {value}")
        return tuple((list(map(int, value.split("."))) + [0, 0, 0, 0])[:4])
    for line in requirements.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_-]+)>=([0-9.]+),<([0-9.]+)", line)
        if not match:
            raise ExperimentError(f"Unsupported dependency constraint; update preflight: {line}")
        name, minimum, maximum = match.groups()
        installed = packages.get(name)
        if installed is None or not numeric(minimum) <= numeric(installed) < numeric(maximum):
            raise ExperimentError(f"Dependency mismatch: {line}, installed {installed}; use a project virtual environment with requirements.txt")

def runtime_snapshot(cfg: dict, root: Path = ROOT, check_version: bool = True) -> dict:
    spec = ADAPTERS[cfg["harness"]]
    if sys.platform != spec["platform"]:
        raise ExperimentError(f"{cfg['harness']} native execution requires {spec['platform']}; plan/report remain cross-platform")
    exe = resolve_executable(cfg)
    probe_env = os.environ.copy()
    probe_env.update(adapter_environment(cfg))
    if cfg["harness"] == "openclaw":
        probe_env["PATH"] = str(Path(cfg["runtime"]["node_executable"]).parent) + os.pathsep + probe_env.get("PATH", "")
    version = probe(exe, root=root, env=probe_env)
    if check_version and version != cfg["expected_version"]:
        raise ExperimentError(f"CLI version mismatch: expected {cfg['expected_version']!r}, got {version!r}. Create a new config/plan for an upgrade.")
    help_text = probe(exe, "exec-help" if cfg["harness"] == "codex" else "help", root, env=probe_env)
    required = {"codex": ["--json", "--model", "--sandbox"],
                "claude": ["--output-format", "--model", "--permission-mode"]}.get(cfg["harness"], [])
    missing = [flag for flag in required if flag not in help_text]
    if missing:
        raise ExperimentError(f"Adapter CLI contract changed; missing flags: {missing}")
    extra = adapter_preflight(cfg, exe, version, root)
    packages = {}
    for name in ("Jinja2", "pandas", "Pillow", "PyYAML"):
        try:
            packages[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            raise ExperimentError(f"Missing fixture dependency {name}; install requirements.txt")
    validate_dependency_versions(packages, root / "requirements.txt")
    return {"harness": cfg["harness"], "executable": str(exe), "executable_sha256": file_hash(exe),
            "cli_version": version, "cli_help_sha256": __import__("hashlib").sha256(help_text.encode()).hexdigest(),
            "python": sys.version, "python_executable": sys.executable, "platform": platform.platform(),
            "powershell": powershell() if sys.platform == "win32" else None, "fixture_dependencies": packages,
            "adapter": extra, "external_inputs": input_inventory(cfg)}

def command_for(cfg: dict, case: dict, job: dict, raw_root: Path, label: str,
                root: Path = ROOT, pwsh: str | None = None) -> list[str]:
    if ADAPTERS[cfg["harness"]]["platform"] == "linux":
        request = raw_root.parent / "request.json"
        write_json(request, {"config": cfg, "case": case, "job": job, "raw_root": str(raw_root), "root": str(root)})
        return [sys.executable, "-m", "harnesssafe.linux_worker", "--request", str(request)]
    args = [pwsh or powershell(), "-NoProfile", "-NonInteractive", "-File",
            str(root / "infra/run_harness_case.ps1"), "-Harness", cfg["harness"],
            "-CaseDir", str(root / "runs" / case["case_dir"]), "-ResultsRoot", str(raw_root),
            "-RunLabel", label, "-Model", cfg["model"], "-PermissionProfile", cfg["permission_profile"],
            "-IsolationMode", "isolated_home", "-TimeoutSec", str(cfg["timeout_seconds"]), "-OutputMode", "minimal"]
    if job["arm"] != "attack":
        args += ["-ControlType", job["arm"]]
    names = {"codex_provider": "CodexProvider", "claude_base_url": "ClaudeBaseUrl",
             "claude_api_key_env": "ClaudeApiKeyEnv", "claude_auth_token_env": "ClaudeAuthTokenEnv"}
    if cfg["harness"] == "hermes":
        names = {"base_url": "HermesBaseUrl", "provider_id": "HermesProviderId",
                 "api_key_env": "HermesApiKeyEnv", "api_mode": "HermesApiMode"}
    elif cfg["harness"] == "openclaw":
        names = {"base_url": "OpenClawBaseUrl", "provider_id": "OpenClawProviderId",
                 "api_key_env": "OpenClawApiKeyEnv", "api": "OpenClawApi"}
        if cfg["runtime"].get("allow_not_run_smoke", False):
            args.append("-OpenClawAllowNotRunSmoke")
    for key, value in sorted(cfg["provider"].items()):
        args += ["-" + names[key], value]
    return args

def launch(args: list[str], cfg: dict, executable: str, log: Path, root: Path = ROOT) -> int:
    env = os.environ.copy()
    env[HARNESS_ENV[cfg["harness"]]] = executable
    env.update(adapter_environment(cfg))
    # The inherited runner launches 'python'; bind it to this experiment's interpreter.
    env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")
    env["PYTHONUTF8"] = "1"
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w", encoding="utf-8") as stream:
        process = subprocess.Popen(args, cwd=root, env=env, stdout=stream, stderr=subprocess.STDOUT,
                                   creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
                                   start_new_session=os.name != "nt")
        try:
            return process.wait()
        except BaseException:
            if process.poll() is None:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True)
                else:
                    import signal
                    os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=30)
            raise


def adapter_environment(cfg: dict) -> dict[str, str]:
    runtime = cfg.get("runtime", {})
    if cfg["harness"] == "hermes":
        return {"HERMES_AGENT_ROOT": runtime["source_root"], "HERMES_PYTHON": runtime["python_executable"],
                "HERMES_GIT_BASH_PATH": runtime["git_bash"], "HERMES_CONFORMANCE": runtime.get("conformance", "")}
    if cfg["harness"] == "openclaw":
        return {"OPENCLAW_NODE_BIN": runtime["node_executable"],
                "OPENCLAW_EXPECTED_NODE_VERSION": runtime["expected_node_version"],
                "OPENCLAW_EXPECTED_VERSION": cfg["expected_version"], "OPENCLAW_CONFORMANCE": runtime.get("conformance", "")}
    return {}


def adapter_preflight(cfg: dict, exe: Path, version: str, root: Path) -> dict:
    harness, runtime = cfg["harness"], cfg.get("runtime", {})
    details = {"scoring": ADAPTERS[harness]["scoring"]}
    def identity(path: Path) -> dict:
        if not path.is_file():
            raise ExperimentError(f"Runtime file missing: {path}")
        return {"path": str(path), "sha256": file_hash(path)}
    if harness == "hermes":
        launcher = Path(runtime["source_root"]) / "hermes"
        details["launcher"] = identity(launcher)
        details["python"] = identity(Path(runtime["python_executable"]))
        details["git_bash"] = identity(Path(runtime["git_bash"]))
        result = subprocess.run([runtime["python_executable"], str(launcher), "--version"],
                                capture_output=True, text=True, timeout=30, encoding="utf-8", errors="replace")
        if result.returncode or result.stdout.strip() != version:
            raise ExperimentError("Hermes probe executable and Python launcher identities differ")
        # The launcher imports this checkout, so pin its tracked Python/config code too.
        paths = []
        for directory, dirs, files in os.walk(runtime["source_root"], followlinks=False):
            dirs[:] = [name for name in dirs if name not in {".git", "venv", ".venv", "__pycache__", "node_modules"}]
            paths.extend(Path(directory) / name for name in files if Path(name).suffix in {".py", ".toml", ".yaml", ".yml"})
        from .common import digest
        details["source_sha256"] = digest({p.relative_to(runtime["source_root"]).as_posix(): file_hash(p) for p in sorted(paths)})
    elif harness == "openclaw":
        node = Path(runtime["node_executable"])
        details["node"] = identity(node)
        observed = probe(node, root=root)
        if observed != runtime["expected_node_version"]:
            raise ExperimentError("OpenClaw Node version differs from expected_node_version")
        details["node"]["version"] = observed
    elif harness in {"gemini", "opencode", "kimi"}:
        details["bubblewrap"] = identity(Path("/usr/bin/bwrap"))
        import importlib
        module = importlib.import_module(f"infra.cross_harness.adapters.{harness}.adapter")
        if harness == "kimi":
            # Production runtime AND analysis are reviewed for this exact runtime only.
            from infra.cross_harness.adapters.kimi.runtime_factory import ReviewedKimiRuntimePins, _validate_runtime_pins
            import tempfile
            with tempfile.TemporaryDirectory(prefix="hs-probe-", dir="/tmp") as directory:
                adapter = module.KimiHarnessAdapter(run_id="preflight", state_root=Path(directory), executable=str(exe))
                observed = adapter.detect_identity()
                pins = ReviewedKimiRuntimePins()
                try:
                    _validate_runtime_pins(pins, observed)
                except RuntimeError as exc:
                    raise ExperimentError("Kimi requires the reviewed 0.26.0 package/Node bytes and paths; update native protocol validation before testing a new version") from exc
                details["reviewed_version"] = pins.version
        else:
            capabilities = importlib.import_module(f"infra.cross_harness.adapters.{harness}.capabilities")
            document = read_json(Path(runtime["conformance"]))
            capabilities._validated_entries(document, evidence_path=Path(runtime["conformance"]))
            semver = re.search(r"(?<![0-9])([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?)", version)
            if not semver or document.get("harness_id") != harness or document.get("harness_version") != semver.group(1) or document.get("executable_sha256") != file_hash(exe):
                raise ExperimentError("Conformance evidence is stale or belongs to a different executable/version")
            details["conformance_sha256"] = file_hash(Path(runtime["conformance"]))
    if harness in {"hermes", "openclaw"}:
        details["native_capabilities"] = windows_capability_preflight(cfg, exe, root)
    return details


def windows_capability_preflight(cfg: dict, exe: Path, root: Path) -> dict:
    import importlib
    from dataclasses import asdict
    native = importlib.import_module(f"infra.harness_adapters.{cfg['harness']}.probe")
    env = os.environ.copy()
    env.update(adapter_environment(cfg))
    if cfg["harness"] == "openclaw":
        env["PATH"] = str(Path(cfg["runtime"]["node_executable"]).parent) + os.pathsep + env.get("PATH", "")
    def run(argv):
        if argv[0] == "git":
            return subprocess.run(argv, capture_output=True, text=True, timeout=30, env=env)
        kind = "version" if list(argv[1:]) == ["--version"] else str(argv[1]) + "-help"
        try:
            output = probe(Path(argv[0]), kind, root, env=env)
            return subprocess.CompletedProcess(argv, 0, stdout=output)
        except ExperimentError:
            return subprocess.CompletedProcess(argv, 1, stdout="")
    kwargs = {"source_root": Path(cfg["runtime"]["source_root"]), "git_run": run} if cfg["harness"] == "hermes" else {}
    identity = native.detect_identity(exe, run, **kwargs)
    path = Path(cfg["runtime"]["conformance"]) if cfg["runtime"].get("conformance") else None
    if not identity.pinned and path is None:
        raise ExperimentError(f"{cfg['harness']} version needs identity-bound runtime.conformance evidence; the inherited pinned version is the only built-in qualification")
    if path:
        from infra.harness_adapters.version_conformance import load_version_conformance
        capability_type = native.HermesCapabilities if cfg["harness"] == "hermes" else native.OpenClawCapabilities
        load_version_conformance(path, harness=cfg["harness"], identity=identity,
                                 capability_names=tuple(capability_type.__dataclass_fields__))
    capabilities = native.probe_capabilities(identity, run, conformance_path=path, use_environment=False)
    result = asdict(capabilities)
    if any(not value["supported"] for value in result.values()):
        raise ExperimentError(f"{cfg['harness']} required native capability checks failed: " +
                              ", ".join(name for name, value in result.items() if not value["supported"]))
    return result
