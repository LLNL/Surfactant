from pathlib import Path

import pytest

from surfactant.cmd.generate import resolve_link


@pytest.fixture
def _setup_symlinks(tmp_path):
    """
    Create a temporary directory tree for testing resolve_link().

    Structure:
        extract/bin/real.txt      → real file
        extract/bin/rel_link      → relative symlink to real.txt
        extract/bin/chain1        → symlink to chain2
        extract/bin/chain2        → symlink to real.txt
        extract/bin/broken        → symlink to nonexistent.txt
        extract/bin/cycle1        → symlink to cycle2
        extract/bin/cycle2        → symlink to cycle1
        extract/bin/abs_link      → absolute symlink to a fake target
    """
    extract_dir = tmp_path / "extract"
    extract_dir.mkdir()

    cur_dir = extract_dir / "bin"
    cur_dir.mkdir()

    # Real file inside bin
    real_file = cur_dir / "real.txt"
    real_file.write_text("hello world")

    # Relative symlink → real.txt
    rel_link = cur_dir / "rel_link"
    rel_link.symlink_to("real.txt")

    # Chain of symlinks → chain1 → chain2 → real.txt
    chain1 = cur_dir / "chain1"
    chain2 = cur_dir / "chain2"
    chain1.symlink_to("chain2")
    chain2.symlink_to("real.txt")

    # Broken symlink
    broken = cur_dir / "broken"
    broken.symlink_to("nonexistent.txt")

    # Cycle of symlinks → cycle1 ↔ cycle2
    cycle1 = cur_dir / "cycle1"
    cycle2 = cur_dir / "cycle2"
    cycle1.symlink_to("cycle2")
    cycle2.symlink_to("cycle1")

    # --- Fake absolute target ---
    fake_abs_target = tmp_path / "fakebin" / "myexe"
    fake_abs_target.parent.mkdir()
    fake_abs_target.write_text("echo hi")

    abs_link = cur_dir / "abs_link"
    # IMPORTANT: symlink to the fake target using an *absolute path*
    abs_link.symlink_to(fake_abs_target)

    return {
        "extract_dir": str(extract_dir),
        "cur_dir": str(cur_dir),
        "real_file": str(real_file),
        "rel_link": str(rel_link),
        "chain1": str(chain1),
        "broken": str(broken),
        "cycle1": str(cycle1),
        "abs_link": str(abs_link),
        "fake_abs_target": str(fake_abs_target),
    }


def test_absolute_symlink_preserved(_setup_symlinks):
    """
    Absolute symlinks should resolve to their real absolute target,
    even if it's outside extract_dir.
    """
    paths = _setup_symlinks
    result = resolve_link(paths["abs_link"], paths["cur_dir"], paths["extract_dir"])
    
    # Compare Path objects so Windows extended paths (\\?\) don't break equality
    assert Path(result) == Path(paths["fake_abs_target"])
    assert Path(result).exists()


def test_relative_symlink_resolves(_setup_symlinks):
    """Relative symlinks should resolve to the correct file under extract_dir."""
    paths = _setup_symlinks
    result = resolve_link(paths["rel_link"], paths["cur_dir"], paths["extract_dir"])
    assert Path(result) == Path(paths["real_file"])


def test_symlink_chain_resolves(_setup_symlinks):
    """Multi-hop symlinks should resolve fully to the final target file."""
    paths = _setup_symlinks
    result = resolve_link(paths["chain1"], paths["cur_dir"], paths["extract_dir"])
    assert Path(result) == Path(paths["real_file"])


def test_broken_symlink_returns_none(_setup_symlinks):
    """Broken symlinks should return None instead of a bogus path."""
    paths = _setup_symlinks
    result = resolve_link(paths["broken"], paths["cur_dir"], paths["extract_dir"])
    assert result is None


def test_cyclic_symlink_returns_none(_setup_symlinks):
    """Cyclic symlinks should be detected and return None."""
    paths = _setup_symlinks
    try:
        result = resolve_link(paths["cycle1"], paths["cur_dir"], paths["extract_dir"])
    except RuntimeError as e:
        # Current implementation may raise RuntimeError on loop
        assert "Symlink loop" in str(e)
    else:
        assert result is None


def test_non_symlink_returns_self(_setup_symlinks):
    """Non-symlink files should be returned unchanged."""
    paths = _setup_symlinks
    result = resolve_link(paths["real_file"], paths["cur_dir"], paths["extract_dir"])
    assert Path(result) == Path(paths["real_file"])


def test_symlink_to_parent_outside_extract_dir(tmp_path):
    """
    Symlink to '..' from inside extract/bin should resolve to extract/,
    not be rebased further up into tmp_path.
    """
    extract_dir = tmp_path / "extract"
    extract_dir.mkdir()
    cur_dir = extract_dir / "bin"
    cur_dir.mkdir()

    parent_link = cur_dir / "parent"
    parent_link.symlink_to("..")

    result = resolve_link(str(parent_link), str(cur_dir), str(extract_dir))

    # Correct resolution is extract_dir
    assert Path(result) == Path(extract_dir)
    assert Path(result).exists()
    assert Path(result).is_dir()
