import hashlib
import os
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from chapter5.archive import pack_state,restore_state,check_previous_session,reserve,close
from chapter5.io import atomic_json,read_json


class ArchiveTests(unittest.TestCase):
    def test_git_reservation_and_failure_archive_resume_preserve_budget(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);remote=root/'remote.git';repo=root/'repo';state=root/'state';cfg={'protocol':'fixture'}
            def command(*args):
                subprocess.run(['git',*map(str,args)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            command('init','--bare',remote);command('clone',remote,repo)
            command('-C',repo,'config','user.name','test');command('-C',repo,'config','user.email','test@example.org')
            (repo/'README.md').write_text('fixture')
            command('-C',repo,'add','README.md');command('-C',repo,'commit','-m','fixture')
            command('-C',repo,'branch','-M','experiment');command('-C',repo,'push','-u','origin','experiment')
            env={'GITHUB_RUN_ID':'1','GITHUB_RUN_ATTEMPT':'1','GITHUB_SHA':'fixture'}
            with patch.dict(os.environ,env):
                reserve(repo,state,cfg,'experiment')
                self.assertEqual(read_json(repo/'chapter5/runs/fixture/session.json')['status'],'active')
                atomic_json(state/'source.request-state.json',{'attempts':3})
                atomic_json(state/'status.json',{'phase':'failed'})
                close(repo,state,cfg,'experiment')
            resumed=root/'resumed'
            with patch.dict(os.environ,dict(env,GITHUB_RUN_ATTEMPT='2')):
                reserve(repo,resumed,cfg,'experiment')
            self.assertEqual(read_json(resumed/'source.request-state.json')['attempts'],3)
            self.assertEqual(read_json(resumed/'execution.json')['attempt'],'2')

    def test_roundtrip_keeps_checkpoints_and_request_budgets_and_rejects_corruption(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);state=root/'state';state.mkdir()
            (state/'checkpoint.pt').write_bytes(bytes(range(256))*10)
            atomic_json(state/'source.request-state.json',{'attempts':3})
            pack_state(state,root/'archive')
            restore_state(root/'archive',root/'restored')
            self.assertEqual((state/'checkpoint.pt').read_bytes(),(root/'restored/checkpoint.pt').read_bytes())
            self.assertEqual((state/'source.request-state.json').read_bytes(),(root/'restored/source.request-state.json').read_bytes())
            part=next((root/'archive').glob('state.part-*'));part.write_bytes(b'broken')
            with self.assertRaises(ValueError):
                restore_state(root/'archive',root/'bad')

    def test_active_previous_run_does_not_silently_reset_budget(self):
        with self.assertRaisesRegex(ValueError,'uncertain'):
            check_previous_session({'status':'active','run_id':'previous'})
        check_previous_session({'status':'closed','run_id':'previous'})

    def test_unsafe_zip_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);archive=root/'archive';archive.mkdir();body=archive/'state.part-000'
            with zipfile.ZipFile(body,'w') as z:
                z.writestr('../escape','unsafe')
            sha=hashlib.sha256(body.read_bytes()).hexdigest()
            atomic_json(archive/'manifest.json',{'schema':'chapter5-state-parts-v1','source_bytes':body.stat().st_size,
                                                'source_sha256':sha,'parts':[{'path':body.name,'sha256':sha,'bytes':body.stat().st_size}]})
            with self.assertRaises(ValueError):
                restore_state(archive,root/'restored')
            self.assertFalse((root/'escape').exists())


if __name__=='__main__':
    unittest.main()
