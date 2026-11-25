from unittest import TestCase
from unittest.mock import patch

from tools.signing import check_upstream as update


class DailyCheckTests(TestCase):
    def test_skips_nightly_draft_and_prerelease_and_resolves_tag(self):
        def release(tag, draft=False, prerelease=False):
            return dict(tag_name=tag, draft=draft, prerelease=prerelease)
        with patch.object(update, "api", side_effect=[
                release("nightly"), [release("nightly"), release("2.1.0", True), release("2.0.0", False, True),
                                     release("1.6.0")], {"sha": "b"*40}]) as calls:
            self.assertEqual(update.latest_release(), ("1.6.0", "b"*40))
            self.assertTrue(calls.call_args.args[0].endswith("/refs/tags/1.6.0"))

    def test_build_decision_requires_usable_kit_from_successful_trusted_run(self):
        source = "f"*40
        ref = dict(id=54, head_branch="master", head_repository_id=4, head_sha="a"*40)
        item = dict(name=f"neutral-windows-x64-54-1-2.0.1-{source}", id=72, size_in_bytes=123,
                    workflow_run=ref, expired=False, digest="sha256:"+"d"*64)
        run = dict(path=update.WORKFLOW, conclusion="success", event="schedule", head_sha="a"*40, repository={"id":4})
        for artifact, status, version, found in [
            (item, run, "2.0.1", True), (item, run, "2.0.2", False),
            (dict(item, expired=True), run, "2.0.1", False),
            (dict(item, workflow_run=dict(ref, head_branch="other")), run, "2.0.1", False),
            (item, dict(run, conclusion="failure"), "2.0.1", False),
            (item, dict(run, path="other.yml"), "2.0.1", False),
        ]:
            with self.subTest(artifact=artifact, status=status, version=version):
                with patch.object(update, "api", side_effect=[{"id":4}, {"artifacts":[artifact]}, status]):
                    kit = next(update.available_kits("owner/repo", "master", (version, source)), None)
                    self.assertEqual(kit is not None, found)
