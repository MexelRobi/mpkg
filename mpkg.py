#!/usr/bin/env python3

import os
import sys
import shutil
import json
import subprocess


# ============================================================
# Configuration
# ============================================================

DB_PATH = "/usr/local/var/mpkg/registry.json"
CACHE_DIR = "/usr/local/var/mpkg/cache"

# Directories that are NEVER allowed to be modified.
# These cannot be overridden by normal package installation.
BLACKLIST = [
    "/System",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/private/var/vm",
    "/etc/master.passwd",
]

# Sensitive directories.
# Installation is possible, but the user must explicitly approve it.
ASK_LIST = [
    "/Applications",
    "/Library",
    "/usr/local/bin",
    "/usr/local/lib",
]

# mpkg's own files.
# Modifying these requires explicit confirmation.
MPKG_PROTECTED = [
    DB_PATH,
    CACHE_DIR,
]


# ============================================================
# Colors
# ============================================================

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[1;36m"
GREEN = "\033[1;32m"
RED = "\033[1;31m"
YELLOW = "\033[1;33m"
MAGENTA = "\033[1;35m"
BLUE = "\033[1;34m"


# ============================================================
# Output helpers
# ============================================================

def print_header(title):
    print(CYAN + "=" * 60)
    print(f" mpkg // {title}")
    print("=" * 60 + RESET)


def print_success(msg):
    print(f"{GREEN}SUCCESS: {msg}{RESET}")


def print_error(msg, exit_code=1):
    print(f"{RED}ERROR: {msg}{RESET}")
    sys.exit(exit_code)


# ============================================================
# Path security
# ============================================================

def normalize_path(path):
    """
    Convert a path into a canonical absolute path.

    This is used for every destination comparison.
    """
    return os.path.realpath(os.path.abspath(os.path.normpath(path)))


def has_traversal(path):
    """
    Reject path components such as:
        .
        ..
        foo/../bar
        ../something

    We intentionally reject them even when they would technically
    resolve to a safe path.
    """
    if not isinstance(path, str):
        return True

    if "\x00" in path:
        return True

    # Backslashes are not valid path separators on macOS,
    # but rejecting them avoids ambiguity between package formats.
    if "\\" in path:
        return True

    if os.path.isabs(path):
        # Absolute paths inside the package are not allowed.
        return True

    components = path.replace(os.sep, "/").split("/")

    for component in components:
        if component in (".", ".."):
            return True

    return False


def is_same_or_inside(path, directory):
    """
    True if path is the directory itself or is located below it.
    """
    path = normalize_path(path)
    directory = normalize_path(directory)

    try:
        return os.path.commonpath([path, directory]) == directory
    except ValueError:
        return False


def path_in_list(path, path_list):
    """
    Check whether a path is inside any protected directory/path.
    """
    path = normalize_path(path)

    for protected in path_list:
        protected = normalize_path(protected)

        if path == protected or is_same_or_inside(path, protected):
            return protected

    return None


def check_path_security(dest):
    """
    Returns:

        ("BLOCKED", reason)
        ("ASK", reason)
        ("OK", None)
    """

    # Destination must always be absolute after construction.
    if not os.path.isabs(dest):
        return "BLOCKED", "Destination path is not absolute."

    dest = normalize_path(dest)

    # --------------------------------------------------------
    # Absolute blacklist
    # --------------------------------------------------------

    blocked = path_in_list(dest, BLACKLIST)

    if blocked:
        return (
            "BLOCKED",
            f"path is inside blacklisted system directory: {blocked}"
        )

    # --------------------------------------------------------
    # mpkg itself
    # --------------------------------------------------------

    mpkg_protected = path_in_list(dest, MPKG_PROTECTED)

    if mpkg_protected:
        return (
            "ASK",
            f"path modifies mpkg protected area: {mpkg_protected}"
        )

    # --------------------------------------------------------
    # Sensitive directories
    # --------------------------------------------------------

    sensitive = path_in_list(dest, ASK_LIST)

    if sensitive:
        return (
            "ASK",
            f"path is inside sensitive directory: {sensitive}"
        )

    return "OK", None


# ============================================================
# Database
# ============================================================

def init_system():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    os.makedirs(CACHE_DIR, exist_ok=True)

    if not os.path.exists(DB_PATH):
        with open(DB_PATH, "w") as f:
            json.dump({}, f, indent=4)


def load_db():
    try:
        with open(DB_PATH, "r") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            print_error("Package registry is corrupted.")

        return data

    except json.JSONDecodeError:
        print_error("Package registry contains invalid JSON.")

    except FileNotFoundError:
        init_system()
        return {}


def save_db(db):
    temp_path = DB_PATH + ".tmp"

    with open(temp_path, "w") as f:
        json.dump(db, f, indent=4)

    os.replace(temp_path, DB_PATH)


# ============================================================
# Package ownership
# ============================================================

def find_file_owner(path, db, ignore_repo=None):
    """
    Find which installed package owns a specific path.

    The same package can be ignored during updates.
    """
    path = normalize_path(path)

    for repo, info in db.items():

        if repo == ignore_repo:
            continue

        for owned_file in info.get("files", []):
            try:
                owned_file = normalize_path(owned_file)
            except Exception:
                continue

            if owned_file == path:
                return repo

    return None


def find_conflicts(files_to_copy, db, current_repo=None):
    """
    Detect package-to-package file conflicts.

    Example:

        Package A -> /usr/local/bin/testcommand
        Package B -> /usr/local/bin/testcommand

    B is rejected and A is reported as the owner.
    """

    conflicts = []

    for src, dest in files_to_copy:

        owner = find_file_owner(
            dest,
            db,
            ignore_repo=current_repo
        )

        if owner:
            conflicts.append({
                "path": dest,
                "owner": owner,
                "incoming": current_repo
            })

    return conflicts


def print_conflicts(conflicts, incoming_repo):
    print(f"\n{RED}{BOLD}PACKAGE CONFLICTS DETECTED{RESET}")
    print()

    for conflict in conflicts:
        print(
            f"{RED}[CONFLICT]{RESET} "
            f"{conflict['path']}"
        )

        print(
            f"           installed: {conflict['owner']}"
        )

        print(
            f"           requested: {incoming_repo}"
        )

        print()


# ============================================================
# Package source analysis
# ============================================================

def analyze_package(pkg_source_dir):
    """
    Analyze the mpkg directory and generate destination paths.

    Returns:
        [(source_path, destination_path), ...]
    """

    files_to_copy = []

    for root, dirs, files in os.walk(
        pkg_source_dir,
        followlinks=False
    ):

        # Reject symlinked directories.
        for directory in list(dirs):
            full_dir = os.path.join(root, directory)

            if os.path.islink(full_dir):
                print_error(
                    f"Package contains a symlinked directory: {full_dir}"
                )

        for file in files:

            src_path = os.path.join(root, file)

            # Reject symlinked files.
            if os.path.islink(src_path):
                print_error(
                    f"Package contains a symlinked file: {src_path}"
                )

            rel_path = os.path.relpath(
                src_path,
                pkg_source_dir
            )

            # ------------------------------------------------
            # Path traversal protection
            # ------------------------------------------------

            if has_traversal(rel_path):
                print_error(
                    f"Unsafe package path detected: {rel_path}"
                )

            # Extra normalization check.
            normalized_rel = os.path.normpath(rel_path)

            if normalized_rel != rel_path:
                print_error(
                    f"Unsafe/non-canonical package path: {rel_path}"
                )

            # Destination always starts at filesystem root.
            dest_path = normalize_path(
                os.path.join("/", rel_path)
            )

            # Prevent escaping /
            if not is_same_or_inside(dest_path, "/"):
                print_error(
                    f"Package path escapes filesystem root: {rel_path}"
                )

            files_to_copy.append(
                (src_path, dest_path)
            )

    return files_to_copy


# ============================================================
# Uninstall
# ============================================================

def uninstall_package(repo, silent=False):
    if not silent:
        print_header(f"Uninstalling {repo}")

    db = load_db()

    if repo not in db:
        if not silent:
            print_error(
                f"Package '{repo}' is not installed."
            )
        return False

    files = db[repo].get("files", [])

    for file in files:

        file = normalize_path(file)

        if os.path.exists(file):

            try:
                # Do not accidentally remove protected system paths.
                security, reason = check_path_security(file)

                if security == "BLOCKED":
                    if not silent:
                        print(
                            f"{RED}Blocked removal: {file}{RESET}"
                        )
                    continue

                os.remove(file)

                if not silent:
                    print(f"Removed: {file}")

                # Remove empty directories upwards.
                dirname = os.path.dirname(file)

                while dirname != "/":

                    # Never delete protected directories.
                    if path_in_list(
                        dirname,
                        BLACKLIST + MPKG_PROTECTED
                    ):
                        break

                    try:
                        if not os.path.isdir(dirname):
                            break

                        if os.listdir(dirname):
                            break

                        os.rmdir(dirname)

                        if not silent:
                            print(
                                f"Removed empty directory: {dirname}"
                            )

                        dirname = os.path.dirname(dirname)

                    except OSError:
                        break

            except Exception as e:

                if not silent:
                    print(
                        f"{RED}Could not remove "
                        f"{file}: {e}{RESET}"
                    )

        else:

            if not silent:
                print(
                    f"Skipped (already missing): {file}"
                )

    del db[repo]
    save_db(db)

    if not silent:
        print_success(
            f"Successfully uninstalled {repo}"
        )

    return True


# ============================================================
# Installation
# ============================================================

def install_package(repo, noclean=False):

    db = load_db()

    # --------------------------------------------------------
    # Validate repository name
    # --------------------------------------------------------

    if not isinstance(repo, str):
        print_error("Invalid repository name.")

    repo = repo.strip()

    if not repo:
        print_error("Repository name cannot be empty.")

    if repo.startswith("-"):
        print_error("Invalid repository name.")

    if repo.count("/") != 1:
        print_error(
            "Repository must have the format: user/repository"
        )

    # --------------------------------------------------------
    # Determine whether this is an update
    # --------------------------------------------------------

    is_update = repo in db

    if is_update:
        print(
            f"{BLUE}-> Package '{repo}' is already installed."
            f"{RESET}"
        )

        print(
            f"{BLUE}-> This installation will replace the "
            f"existing version.{RESET}"
        )

    print_header(
        f"{'Updating' if is_update else 'Installing'} {repo}"
    )

    # --------------------------------------------------------
    # Clone repository into cache
    # --------------------------------------------------------

    repo_url = f"https://github.com/{repo}.git"

    target_cache = os.path.join(
        CACHE_DIR,
        repo.replace("/", "_")
    )

    if os.path.exists(target_cache):
        shutil.rmtree(target_cache)

    print(
        f"-> Cloning repository from {repo_url}..."
    )

    try:
        subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                repo_url,
                target_cache
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    except subprocess.CalledProcessError:
        print_error(
            "Failed to clone repository. "
            "Check the repository name or network connection."
        )

    # --------------------------------------------------------
    # mpkg folder
    # --------------------------------------------------------

    pkg_source_dir = os.path.join(
        target_cache,
        "mpkg"
    )

    if not os.path.isdir(pkg_source_dir):
        print_error(
            "The 'mpkg' directory was not found "
            "inside the repository."
        )

    # --------------------------------------------------------
    # mpkgexec
    # --------------------------------------------------------

    exec_script_src = os.path.join(
        target_cache,
        "mpkgexec"
    )

    has_exec_script = (
        os.path.isfile(exec_script_src)
    )

    if os.path.islink(exec_script_src):
        print_error(
            "The 'mpkgexec' file must not be a symlink."
        )

    # --------------------------------------------------------
    # Remove .git before deployment
    # --------------------------------------------------------

    git_dir = os.path.join(
        target_cache,
        ".git"
    )

    if os.path.exists(git_dir):
        shutil.rmtree(git_dir)

    # --------------------------------------------------------
    # Analyze package
    # --------------------------------------------------------

    files_to_copy = analyze_package(
        pkg_source_dir
    )

    if not files_to_copy:
        print_error(
            "No files found inside the 'mpkg' directory."
        )

    # --------------------------------------------------------
    # Security analysis
    # --------------------------------------------------------

    print(
        f"\n{YELLOW}Target Paths Overview:{RESET}"
    )

    requires_approval = False

    for src, dest in files_to_copy:

        status, reason = check_path_security(dest)

        if status == "BLOCKED":

            print(
                f"  {RED}[BLOCKED]{RESET} "
                f"{dest}"
            )

            print(
                f"           {reason}"
            )

            # Entire installation is aborted.
            print_error(
                "Installation aborted due to "
                "blacklisted/unsafe path."
            )

        elif status == "ASK":

            print(
                f"  {MAGENTA}[SENSITIVE]{RESET} "
                f"{dest}"
            )

            print(
                f"           {reason}"
            )

            requires_approval = True

        else:

            print(
                f"  {GREEN}[OK]{RESET} "
                f"{dest}"
            )

    # --------------------------------------------------------
    # Package ownership conflicts
    # --------------------------------------------------------

    conflicts = find_conflicts(
        files_to_copy,
        db,
        current_repo=repo
    )

    if conflicts:

        print_conflicts(
            conflicts,
            repo
        )

        print_error(
            "Installation aborted because another "
            "installed package owns one or more "
            "target paths."
        )

    # --------------------------------------------------------
    # Post-install script
    # --------------------------------------------------------

    if has_exec_script:

        print(
            f"  {BLUE}[SCRIPT]{RESET} "
            "mpkgexec (will run post-install)"
        )

    # --------------------------------------------------------
    # Sensitive path confirmation
    # --------------------------------------------------------

    if requires_approval:

        print(
            f"\n{MAGENTA}{BOLD}"
            "WARNING: This package modifies "
            "protected/sensitive directories."
            f"{RESET}"
        )

        print(
            "The affected paths were shown above."
        )

        choice = input(
            "\nDo you explicitly allow these "
            "modifications? (y/N): "
        ).strip().lower()

        if choice != "y":

            print_error(
                "Installation cancelled by user."
            )

    # --------------------------------------------------------
    # Installation confirmation
    # --------------------------------------------------------

    choice = input(
        "\nDo you want to proceed with the "
        "installation? (y/N): "
    ).strip().lower()

    if choice != "y":

        print_error(
            "Installation cancelled by user."
        )

    # --------------------------------------------------------
    # Update:
    # Remove old version ONLY after all checks succeeded.
    # --------------------------------------------------------

    if is_update:

        print(
            f"\n{BLUE}-> Removing previous version...{RESET}"
        )

        if not uninstall_package(
            repo,
            silent=True
        ):
            print_error(
                "Failed to remove previous package version."
            )

        print(
            f"{BLUE}-> Previous version removed."
            f"{RESET}"
        )

    # --------------------------------------------------------
    # Copy files
    # --------------------------------------------------------

    installed_files = []

    print(
        f"\n{BLUE}-> Deploying package files..."
        f"{RESET}"
    )

    try:

        for src, dest in files_to_copy:

            # Re-check security immediately before writing.
            status, reason = check_path_security(dest)

            if status == "BLOCKED":
                raise RuntimeError(
                    f"Security check failed for {dest}: {reason}"
                )

            parent = os.path.dirname(dest)

            os.makedirs(
                parent,
                exist_ok=True
            )

            shutil.copy2(
                src,
                dest
            )

            installed_files.append(dest)

            # Remove macOS quarantine.
            subprocess.run(
                [
                    "xattr",
                    "-d",
                    "com.apple.quarantine",
                    dest
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            # ------------------------------------------------
            # Executable detection
            # ------------------------------------------------

            filename = os.path.basename(dest)

            path_components = dest.split(os.sep)

            is_executable_path = (
                "bin" in path_components
                or "sbin" in path_components
            )

            has_executable_ext = (
                filename.endswith(".py")
                or filename.endswith(".sh")
            )

            is_extensionless = (
                "." not in filename
            )

            if (
                is_executable_path
                or has_executable_ext
                or is_extensionless
            ):

                os.chmod(
                    dest,
                    0o755
                )

                print(
                    f"{GREEN}Deployed & Executable:"
                    f"{RESET} {dest}"
                )

            else:

                print(
                    f"Deployed: {dest}"
                )

    except Exception as e:

        print(
            f"{RED}Installation failed: {e}{RESET}"
        )

        # Best-effort rollback of files belonging to
        # this installation.
        print(
            f"{YELLOW}-> Rolling back installed files..."
            f"{RESET}"
        )

        for installed in reversed(
            installed_files
        ):

            try:
                if os.path.isfile(installed):
                    os.remove(installed)
            except Exception:
                pass

        print_error(
            "Installation rolled back."
        )

    # --------------------------------------------------------
    # Post-install script
    # --------------------------------------------------------

    if has_exec_script:

        print(
            f"-> Running post-install script "
            f"(mpkgexec)..."
        )

        try:

            os.chmod(
                exec_script_src,
                0o755
            )

            subprocess.run(
                [
                    "xattr",
                    "-d",
                    "com.apple.quarantine",
                    exec_script_src
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            subprocess.run(
                [exec_script_src],
                check=True
            )

            print(
                "-> Post-install script "
                "finished successfully."
            )

        except subprocess.CalledProcessError:

            print(
                f"{YELLOW}WARNING: "
                "Post-install script exited "
                f"with an error.{RESET}"
            )

    # --------------------------------------------------------
    # Registry
    # --------------------------------------------------------

    db = load_db()

    db[repo] = {
        "files": installed_files,
        "noclean": bool(noclean)
    }

    save_db(db)

    print_success(
        f"Successfully installed {repo} "
        f"(noclean={noclean})"
    )

    if is_update:
        print_success(
            f"Package {repo} was updated successfully."
        )


# ============================================================
# List
# ============================================================

def list_packages():

    print_header(
        "Installed Packages"
    )

    db = load_db()

    if not db:

        print(
            "No packages installed."
        )

        return

    for repo, info in db.items():

        flag = (
            " [NO-CLEAN]"
            if info.get("noclean")
            else ""
        )

        print(
            f"* {GREEN}{repo}{RESET}"
            f"{flag} "
            f"({len(info.get('files', []))} files)"
        )


# ============================================================
# Clean
# ============================================================

def clean_all():

    print_header(
        "Deep Cleaning mpkg System"
    )

    db = load_db()

    to_delete = []

    for repo, info in list(db.items()):

        if info.get("noclean"):

            print(
                f"Skipping {BLUE}{repo}{RESET} "
                "(--noclean protected)"
            )

            continue

        print(
            f"Queueing {RED}{repo}{RESET} "
            "for removal..."
        )

        to_delete.append(repo)

    for repo in to_delete:

        uninstall_package(
            repo,
            silent=True
        )

    if os.path.exists(CACHE_DIR):

        # CACHE_DIR itself is protected from package writes,
        # but mpkg's own clean operation is allowed to remove it.
        shutil.rmtree(CACHE_DIR)

        print(
            "Cache cleared."
        )

    os.makedirs(
        CACHE_DIR,
        exist_ok=True
    )

    print_success(
        "Clean operation finished."
    )


# ============================================================
# CLI
# ============================================================

def print_usage():

    print(
        "Usage:"
    )

    print(
        "  mpkg -i <user/repo> [--noclean]"
    )

    print(
        "  mpkg -u <user/repo>"
    )

    print(
        "  mpkg -l"
    )

    print(
        "  mpkg -clean"
    )


def main():

    # --------------------------------------------------------
    # Root check
    # --------------------------------------------------------

    if os.geteuid() != 0:

        print_error(
            "mpkg requires root privileges. "
            "Please run with 'sudo mpkg'."
        )

    init_system()

    # --------------------------------------------------------
    # Arguments
    # --------------------------------------------------------

    if len(sys.argv) < 2:

        print_usage()
        sys.exit(1)

    action = sys.argv[1]

    # --------------------------------------------------------
    # Install
    # --------------------------------------------------------

    if action == "-i":

        if len(sys.argv) < 3:

            print_error(
                "Please specify a GitHub repository "
                "(e.g. 'user/repo')."
            )

        repo = sys.argv[2]

        noclean = (
            "--noclean" in sys.argv[3:]
        )

        install_package(
            repo,
            noclean
        )

    # --------------------------------------------------------
    # Uninstall
    # --------------------------------------------------------

    elif action == "-u":

        if len(sys.argv) < 3:

            print_error(
                "Please specify a GitHub repository "
                "to uninstall."
            )

        repo = sys.argv[2]

        uninstall_package(
            repo
        )

    # --------------------------------------------------------
    # List
    # --------------------------------------------------------

    elif action == "-l":

        list_packages()

    # --------------------------------------------------------
    # Clean
    # --------------------------------------------------------

    elif action == "-clean":

        clean_all()

    # --------------------------------------------------------
    # Unknown
    # --------------------------------------------------------

    else:

        print_error(
            f"Unknown command '{action}'"
        )


if __name__ == "__main__":
    main()