#!/usr/bin/env python3
"""
Python Environment Type Detector and Package Injector

Detects if the current Python environment is managed by:
- uv (as a tool installation)
- pipx (as a tool installation)
- uv (as a virtual environment)

Also provides functionality to:
- Find binaries in the environment
- Inject packages into the current environment
"""

import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from textwrap import dedent
from typing import Sequence


class EnvType(Enum):
    """Types of Python environments that can be detected."""
    UV_TOOL = auto()
    PIPX = auto()
    UV_VENV = auto()
    STANDARD_VENV = auto()
    SYSTEM = auto()
    UNKNOWN = auto()


@dataclass(frozen=True)
class EnvInfo:
    """Information about the detected Python environment."""
    env_type: EnvType
    path: Path
    details: dict[str, str | Path | None]
    binaries: list[Path] = field(default_factory=list)

    def __str__(self) -> str:
        lines = [f"Environment Type: {self.env_type.name}"]
        lines.append(f"Path: {self.path}")
        if self.details:
            lines.append("Details:")
            for key, value in self.details.items():
                lines.append(f"  {key}: {value}")
        if self.binaries:
            lines.append(f"Binaries found: {len(self.binaries)}")
            for binary in self.binaries[:10]:  # Show first 10
                lines.append(f"  - {binary.name}")
            if len(self.binaries) > 10:
                lines.append(f"  ... and {len(self.binaries) - 10} more")
        return "\n".join(lines)


class EnvironmentDetector:
    """Detects the type of Python environment currently running."""

    def __init__(self) -> None:
        self.prefix = Path(sys.prefix)
        self.base_prefix = Path(sys.base_prefix)
        self.executable = Path(sys.executable)

    def detect(self) -> EnvInfo:
        """
        Detect the current environment type.
        
        Returns:
            EnvInfo object containing environment type and details
        """
        # Check for virtual environment first
        if not self._is_venv():
            binaries = self._find_binaries()
            return EnvInfo(
                env_type=EnvType.SYSTEM,
                path=self.prefix,
                details={"executable": self.executable},
                binaries=binaries
            )

        # Now check what type of venv/tool it is
        if env_info := self._check_uv_tool():
            return env_info
        
        if env_info := self._check_pipx():
            return env_info
        
        if env_info := self._check_uv_venv():
            return env_info
        
        if env_info := self._check_standard_venv():
            return env_info

        binaries = self._find_binaries()
        return EnvInfo(
            env_type=EnvType.UNKNOWN,
            path=self.prefix,
            details={"executable": self.executable},
            binaries=binaries
        )

    def _is_venv(self) -> bool:
        """Check if running in any virtual environment."""
        return self.prefix != self.base_prefix

    def _find_binaries(self) -> list[Path]:
        """Find all executable binaries in the environment's bin/Scripts directory."""
        binaries = []
        
        # Check both Unix (bin) and Windows (Scripts) directories
        for bin_dir_name in ("bin", "Scripts"):
            bin_dir = self.prefix / bin_dir_name
            if bin_dir.exists() and bin_dir.is_dir():
                for item in bin_dir.iterdir():
                    if item.is_file() and self._is_executable(item):
                        binaries.append(item)
        
        return sorted(binaries, key=lambda p: p.name.lower())

    @staticmethod
    def _is_executable(path: Path) -> bool:
        """Check if a file is executable."""
        try:
            # On Unix, check execute permission
            if hasattr(path, 'stat'):
                return bool(path.stat().st_mode & 0o111)
        except (OSError, PermissionError):
            pass
        
        # On Windows, consider common executable extensions
        return path.suffix.lower() in {".exe", ".bat", ".cmd", ".ps1", ""} or path.is_file()

    def _check_uv_tool(self) -> EnvInfo | None:
        """
        Check if this is a uv tool installation.
        
        uv tool installs are located at:
        - Unix: ~/.local/share/uv/tools/<package>/
        - Windows: %LOCALAPPDATA%/uv/tools/<package>/
        """
        parts = self.prefix.parts
        
        # Check if path contains uv/tools pattern
        if "uv" in parts and "tools" in parts:
            try:
                tools_idx = parts.index("tools")
                uv_idx = parts.index("uv")
                
                # Verify uv comes before tools in the path
                if uv_idx < tools_idx and tools_idx + 1 < len(parts):
                    tool_name = parts[tools_idx + 1]
                    
                    # Check for uv.toml or .uv marker
                    uv_toml = self.prefix / "uv.toml"
                    uv_marker = self.prefix / ".uv"
                    
                    binaries = self._find_binaries()
                    
                    return EnvInfo(
                        env_type=EnvType.UV_TOOL,
                        path=self.prefix,
                        details={
                            "tool_name": tool_name,
                            "has_uv_toml": uv_toml.exists(),
                            "has_uv_marker": uv_marker.exists(),
                        },
                        binaries=binaries
                    )
            except (ValueError, IndexError):
                pass
        
        return None

    def _check_pipx(self) -> EnvInfo | None:
        """
        Check if this is a pipx installation.
        
        pipx installs are located at:
        - Unix: ~/.local/pipx/venvs/<package>/
        - Windows: %USERPROFILE%/.local/pipx/venvs/<package>/
        """
        parts = self.prefix.parts
        
        # Check if path contains pipx/venvs pattern
        if "pipx" in parts and "venvs" in parts:
            try:
                venvs_idx = parts.index("venvs")
                pipx_idx = parts.index("pipx")
                
                # Verify pipx comes before venvs
                if pipx_idx < venvs_idx and venvs_idx + 1 < len(parts):
                    package_name = parts[venvs_idx + 1]
                    
                    # Check for pipx metadata
                    pipx_metadata = self.prefix / "pipx_metadata.json"
                    
                    binaries = self._find_binaries()
                    
                    return EnvInfo(
                        env_type=EnvType.PIPX,
                        path=self.prefix,
                        details={
                            "package_name": package_name,
                            "has_metadata": pipx_metadata.exists(),
                        },
                        binaries=binaries
                    )
            except (ValueError, IndexError):
                pass
        
        return None

    def _check_uv_venv(self) -> EnvInfo | None:
        """
        Check if this is a uv-managed virtual environment.
        
        uv venvs have a .uv marker file or pyvenv.cfg with uv references.
        """
        # Check for .uv marker (uv 0.4+)
        uv_marker = self.prefix / ".uv"
        if uv_marker.exists():
            binaries = self._find_binaries()
            return EnvInfo(
                env_type=EnvType.UV_VENV,
                path=self.prefix,
                details={
                    "marker_file": uv_marker,
                    "created_by": "uv",
                },
                binaries=binaries
            )
        
        # Check pyvenv.cfg for uv signatures
        pyvenv_cfg = self.prefix / "pyvenv.cfg"
        if pyvenv_cfg.exists():
            try:
                content = pyvenv_cfg.read_text()
                if "uv" in content.lower():
                    binaries = self._find_binaries()
                    return EnvInfo(
                        env_type=EnvType.UV_VENV,
                        path=self.prefix,
                        details={
                            "pyvenv_cfg": pyvenv_cfg,
                            "created_by": "uv (detected in pyvenv.cfg)",
                        },
                        binaries=binaries
                    )
            except (OSError, UnicodeDecodeError):
                pass
        
        return None

    def _check_standard_venv(self) -> EnvInfo | None:
        """Check if this is a standard venv/virtualenv."""
        pyvenv_cfg = self.prefix / "pyvenv.cfg"
        
        if pyvenv_cfg.exists():
            binaries = self._find_binaries()
            return EnvInfo(
                env_type=EnvType.STANDARD_VENV,
                path=self.prefix,
                details={
                    "pyvenv_cfg": pyvenv_cfg,
                    "created_by": "venv or virtualenv",
                },
                binaries=binaries
            )
        
        return None


class PackageInjector:
    """Injects packages into the current Python environment."""

    def __init__(self, env_info: EnvInfo) -> None:
        self.env_info = env_info
        self.python_exe = Path(sys.executable)

    def inject(
        self,
        packages: str | Sequence[str],
        *,
        upgrade: bool = False,
        no_deps: bool = False,
        dry_run: bool = False,
    ) -> subprocess.CompletedProcess:
        """
        Inject package(s) into the current environment.

        Args:
            packages: Package name(s) to install
            upgrade: Whether to upgrade if already installed
            no_deps: Don't install dependencies
            dry_run: Show what would be done without doing it

        Returns:
            CompletedProcess from the installation command

        Raises:
            RuntimeError: If not in a virtual environment
            subprocess.CalledProcessError: If installation fails
        """
        if self.env_info.env_type == EnvType.SYSTEM:
            raise RuntimeError(
                "Cannot inject packages into system Python. "
                "Please use a virtual environment."
            )

        # Normalize packages to list
        if isinstance(packages, str):
            packages = [packages]

        # Build the appropriate command based on environment type
        cmd = self._build_install_command(packages, upgrade, no_deps)

        if dry_run:
            self._print_dry_run_info(packages, cmd, upgrade, no_deps)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        print(f"Installing: {', '.join(packages)}")
        print(f"Command: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
            )
            print("Installation successful!")
            if result.stdout:
                print(result.stdout)
            return result
        except subprocess.CalledProcessError as e:
            print(f"Installation failed with exit code {e.returncode}")
            if e.stderr:
                print(f"Error: {e.stderr}")
            raise

    def _print_dry_run_info(
        self,
        packages: Sequence[str],
        cmd: list[str],
        upgrade: bool,
        no_deps: bool,
    ) -> None:
        """Print detailed information about what would be done in a dry run."""
        # Format package list
        package_list = "\n".join(f"  • {pkg}" for pkg in packages)
        
        # Determine installation method description
        method_info = self._get_installation_method_info()
        
        # Build the complete dry-run output using a multi-line f-string with dedent
        output = dedent(f"""\
            {'=' * 70}
            DRY RUN MODE - No changes will be made
            {'=' * 70}
            
            Environment Information:
              Type: {self.env_info.env_type.name}
              Path: {self.env_info.path}
              Python: {self.python_exe}
            
            Packages to Install:
            {package_list}
            
            Installation Options:
              Upgrade if exists: {upgrade}
              Skip dependencies: {no_deps}
            
            Command to Execute:
              {' '.join(cmd)}
            
            Installation Method:
            {method_info}
            
            {'=' * 70}
            To actually install, run without --dry-run flag
            {'=' * 70}
        """)
        
        print(output)

    def _get_installation_method_info(self) -> str:
        """Get formatted installation method information."""
        match self.env_info.env_type:
            case EnvType.UV_TOOL:
                lines = ["  Using 'uv pip install' for uv tool environment"]
                if tool_name := self.env_info.details.get("tool_name"):
                    lines.append(f"  Tool: {tool_name}")
                return "\n".join(lines)
            
            case EnvType.UV_VENV:
                return "  Using 'uv pip install' for uv virtual environment"
            
            case EnvType.PIPX:
                lines = ["  Using 'pipx inject' for pipx environment"]
                if pkg_name := self.env_info.details.get("package_name"):
                    lines.append(f"  Package: {pkg_name}")
                return "\n".join(lines)
            
            case EnvType.STANDARD_VENV:
                return "  Using 'pip install' for standard virtual environment"
            
            case _:
                return "  Using 'pip install' (fallback)"

    def _build_install_command(
        self,
        packages: Sequence[str],
        upgrade: bool,
        no_deps: bool,
    ) -> list[str]:
        """Build the appropriate installation command based on env type."""
        match self.env_info.env_type:
            case EnvType.UV_TOOL | EnvType.UV_VENV:
                return self._build_uv_command(packages, upgrade, no_deps)
            case EnvType.PIPX:
                return self._build_pipx_command(packages, upgrade)
            case _:
                return self._build_pip_command(packages, upgrade, no_deps)

    def _build_uv_command(
        self,
        packages: Sequence[str],
        upgrade: bool,
        no_deps: bool,
    ) -> list[str]:
        """Build uv pip install command."""
        cmd = ["uv", "pip", "install"]
        
        if upgrade:
            cmd.append("--upgrade")
        
        if no_deps:
            cmd.append("--no-deps")
        
        cmd.extend(packages)
        return cmd

    def _build_pipx_command(
        self,
        packages: Sequence[str],
        upgrade: bool,
    ) -> list[str]:
        """Build pipx inject command."""
        if not self.env_info.details.get("package_name"):
            raise RuntimeError("Cannot determine pipx package name")
        
        package_name = self.env_info.details["package_name"]
        cmd = ["pipx", "inject", str(package_name)]
        
        if upgrade:
            cmd.append("--force")
        
        cmd.extend(packages)
        return cmd

    def _build_pip_command(
        self,
        packages: Sequence[str],
        upgrade: bool,
        no_deps: bool,
    ) -> list[str]:
        """Build standard pip install command."""
        cmd = [str(self.python_exe), "-m", "pip", "install"]
        
        if upgrade:
            cmd.append("--upgrade")
        
        if no_deps:
            cmd.append("--no-deps")
        
        cmd.extend(packages)
        return cmd


def main() -> None:
    """Main entry point for the detector and injector."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Detect Python environment type and inject packages"
    )
    parser.add_argument(
        "--inject",
        nargs="+",
        metavar="PACKAGE",
        help="Package(s) to inject into the current environment",
    )
    parser.add_argument(
        "--upgrade",
        action="store_true",
        help="Upgrade package if already installed",
    )
    parser.add_argument(
        "--no-deps",
        action="store_true",
        help="Don't install dependencies",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without doing it",
    )
    parser.add_argument(
        "--list-binaries",
        action="store_true",
        help="List all binaries in the environment",
    )

    args = parser.parse_args()

    # Detect environment
    detector = EnvironmentDetector()
    env_info = detector.detect()
    
    print(env_info)
    print()

    # List binaries if requested
    if args.list_binaries and env_info.binaries:
        print("All binaries:")
        for binary in env_info.binaries:
            print(f"  {binary}")
        print()

    # Inject packages if requested
    if args.inject:
        injector = PackageInjector(env_info)
        try:
            injector.inject(
                args.inject,
                upgrade=args.upgrade,
                no_deps=args.no_deps,
                dry_run=args.dry_run,
            )
        except (RuntimeError, subprocess.CalledProcessError) as e:
            print(f"Error: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()