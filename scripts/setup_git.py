"""
SentinelAegis-X - Git Remote Synchronizer
Quick script to bind your local repository to a remote GitHub or GitLab repository.
Usage: python scripts/setup_git.py https://github.com/USER/REPO.git
"""

import sys
import subprocess


def push_to_remote(remote_url: str):
    print(f"[*] Binding repository to remote: {remote_url}")
    subprocess.run("git branch -M main", shell=True)
    subprocess.run(f"git remote remove origin", shell=True, stderr=subprocess.DEVNULL)
    subprocess.run(f"git remote add origin {remote_url}", shell=True)
    res = subprocess.run("git push -u origin main", shell=True)
    if res.returncode == 0:
        print("[+] All code successfully synchronized to remote repository!")
    else:
        print("[-] Push encountered an issue. Ensure credentials and remote permissions are configured.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/setup_git.py <REMOTE_GIT_URL>")
        sys.exit(1)
    push_to_remote(sys.argv[1])
