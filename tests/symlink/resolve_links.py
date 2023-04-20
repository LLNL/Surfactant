from surfactant.cmd.generate import resolve_link
import pathlib
import os

base_dir = pathlib.Path(__file__).parent.absolute()

def symlink(src, dst, target_is_directory):
    try:
        os.symlink(src, dst, target_is_directory)
    except FileExistsError:
        pass

def create_symlinks():
    # Make sure this is always the working directory
    os.chdir(base_dir)
    os.makedirs('test_dir/subdir', exist_ok=True)
    os.chdir('test_dir')
    symlink('..', 'parent', True)
    symlink('parent', 'link_to_parent', True)
    symlink('/none/', 'does_not_exist', True)
    symlink('..', 'subdir/parent', True)
    # Revert back to the original working directory
    os.chdir(base_dir)

def run_tests():
    create_symlinks()
    base_path = os.path.realpath(os.path.join(base_dir, 'test_dir'))
    assert resolve_link(os.path.join(base_path, 'parent'), base_path, base_path) == base_path
    assert resolve_link(os.path.join(base_path, 'link_to_parent'), base_path, base_path) == base_path
    assert resolve_link(os.path.join(base_path, 'does_not_exist'), base_path, base_path) is None
    assert resolve_link(os.path.join(base_path, 'subdir', 'parent'), os.path.join(base_path, 'subdir'), base_path) == base_path

if __name__ == '__main__':
    run_tests()
