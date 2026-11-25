"""Decide whether the latest stable RustDesk release needs a Windows kit."""
import json
import os
import re
import subprocess

STABLE = r"[0-9]+\.[0-9]+\.[0-9]+"
COMMIT = r"[a-f0-9]{40}"
LEGACY_VERSION = "1.5.3"
LEGACY_SOURCE = "95cca3f661f635b3cc85c04935fe8d96d8f432ef"
WORKFLOW = ".github/workflows/neutral-windows.yml"


def api(path):
    return json.loads(subprocess.check_output(["gh", "api", "--hostname", "github.com", path], text=True))


def stable_release(release):
    return (not release["draft"] and not release["prerelease"]
            and re.fullmatch(STABLE, release["tag_name"]))


def stable_tag():
    latest = api("repos/rustdesk/rustdesk/releases/latest")
    if stable_release(latest):
        return latest["tag_name"]
    for page in range(1, 10000):
        releases = api(f"repos/rustdesk/rustdesk/releases?per_page=100&page={page}")
        for release in releases:
            if stable_release(release):
                return release["tag_name"]
        if len(releases) < 100:
            break
    raise ValueError("No stable upstream release found")


def latest_release():
    tag = stable_tag()
    source = api("repos/rustdesk/rustdesk/commits/refs/tags/" + tag)["sha"]
    if not re.fullmatch(COMMIT, source):
        raise ValueError("Invalid upstream commit")
    return tag, source


def available_kits(repo, branch, wanted=None):
    repo_id = api(f"repos/{repo}")["id"]
    for page in range(1, 10000):
        artifacts = api(f"repos/{repo}/actions/artifacts?per_page=100&page={page}")["artifacts"]
        for item in artifacts:
            match = re.fullmatch(rf"neutral-windows-x64-([1-9][0-9]*)-([1-9][0-9]*)(?:-({STABLE})-({COMMIT}))?", item["name"])
            if not match or item["expired"]:
                continue
            run_id, attempt, version, source = match.groups()
            run_ref = item.get("workflow_run") or {}
            if (str(run_ref.get("id")) != run_id or run_ref.get("head_branch") != branch
                    or run_ref.get("head_repository_id") != repo_id):
                continue
            if version is None:
                # Legacy artifacts used a fixed source pin in the workflow.
                if run_ref["head_sha"] != "a6e6de9c87bc06064609436c33d7ab46adfac837":
                    continue
                version, source = LEGACY_VERSION, LEGACY_SOURCE
            if wanted and wanted != (version, source):
                continue
            run = api(f"repos/{repo}/actions/runs/{run_id}/attempts/{attempt}")
            if (run["path"] != WORKFLOW or run["conclusion"] != "success"
                    or run["event"] not in ("workflow_dispatch", "schedule")
                    or run["head_sha"] != run_ref["head_sha"] or run["repository"]["id"] != repo_id):
                continue
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", item.get("digest") or ""):
                raise ValueError("GitHub did not supply an artifact SHA-256")
            yield dict(version=version, source=source, run=run_id, attempt=attempt, revision=run["head_sha"],
                       artifact=item["id"], digest=item["digest"][7:], size=item["size_in_bytes"])
        if len(artifacts) < 100:
            break


if __name__ == "__main__":
    version, source = latest_release()
    repo = os.environ["GITHUB_REPOSITORY"]
    branch = os.environ["DEFAULT_BRANCH"]
    existing = next(available_kits(repo, branch, (version, source)), None)
    build = existing is None or os.environ.get("FORCE_REBUILD") == "true"
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        print(f"version={version}\nsource={source}\nbuild={str(build).lower()}", file=output)
    message = f"RustDesk {version} ({source}): "
    message += "build requested." if build else f"kit available from run {existing['run']}."
    print(message)
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
        print(message, file=summary)
        if existing:
            print(f"\n[Download the ZIP from the successful run](https://github.com/{repo}/actions/runs/{existing['run']})", file=summary)
