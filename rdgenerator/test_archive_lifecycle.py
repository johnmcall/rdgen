import json
from django.test import TestCase, override_settings

@override_settings(RDGEN_CALLBACK_SECRET='unit-test-callback-value', ALLOWED_HOSTS=['testserver'])
class ArchiveLifecycleTests(TestCase):
    def setUp(self):
        import tempfile, os
        self.old_cwd = os.getcwd()
        self.tmp = tempfile.TemporaryDirectory()
        os.chdir(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(os.chdir,self.old_cwd)
    def generate(self):
        from unittest.mock import patch,Mock
        from rdgenerator.views import generate_custom_client
        github=Mock(status_code=200)
        github.json.return_value={'workflow_run_id':123,'html_url':''}
        with patch('rdgenerator.views.requests.post',return_value=github):
            return generate_custom_client({'platform':'windows','version':'1.5.3','exename':'client'},'https://rdgen.example.com')
    def test_completed_build_cleanup_removes_its_archive_only(self):
        from pathlib import Path
        result=self.generate()
        self.assertTrue(result['success'])
        archives=list(Path('temp_zips').glob('*.zip'))
        self.assertEqual(len(archives),1)
        unrelated=Path('temp_zips/secrets_00000000-0000-0000-0000-000000000001.zip')
        unrelated.write_bytes(b'unrelated')
        r=self.client.post('/cleanzip',json.dumps({'uuid':result['uuid']}),content_type='application/json',HTTP_X_RDGEN_CALLBACK='unit-test-callback-value')
        self.assertEqual(r.status_code,200)
        self.assertFalse(archives[0].exists())
        self.assertEqual(unrelated.read_bytes(),b'unrelated')
    def test_generation_does_not_stage_plaintext_settings_on_disk(self):
        import builtins
        from pathlib import Path
        from unittest.mock import patch
        original=builtins.open
        def open_without_plaintext(file,*args,**kwargs):
            if str(file).startswith('data_'):
                raise AssertionError('Plaintext settings staging is forbidden')
            return original(file,*args,**kwargs)
        with patch('builtins.open',side_effect=open_without_plaintext):
            result=self.generate()
        self.assertTrue(result['success'])
        self.assertEqual(list(Path('.').glob('data_*.json')),[])
    def test_cleanup_rejects_partial_identifier(self):
        from pathlib import Path
        Path('temp_zips').mkdir()
        f=Path('temp_zips/secrets_ee11ee11-ee11-ee11-ee11-ee11ee11ee11.zip')
        f.write_bytes(b'untouched')
        r=self.client.post('/cleanzip',json.dumps({'uuid':'ee11'}),content_type='application/json',HTTP_X_RDGEN_CALLBACK='unit-test-callback-value')
        self.assertEqual(r.status_code,400)
        self.assertTrue(f.exists())
