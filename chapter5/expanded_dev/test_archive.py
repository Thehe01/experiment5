import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from chapter5.archive import git
from chapter5.io import atomic_json,sha_file
from chapter5.expanded_dev.archive import reserve,close

class ArchiveTests(unittest.TestCase):
    def test_bare_git_reservation_unknown_runner_restore_and_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp=Path(tmp);bare=tmp/'origin';repo=tmp/'repo';state=tmp/'state'
            subprocess.run(['git','init','--bare',str(bare)],check=True,capture_output=True)
            subprocess.run(['git','clone',str(bare),str(repo)],check=True,capture_output=True)
            git(repo,'config','user.name','test');git(repo,'config','user.email','test@example.invalid')
            (repo/'seed.txt').write_text('frozen\n');git(repo,'add','.');git(repo,'commit','-m','source')
            source=git(repo,'rev-parse','HEAD',capture=True);branch='codex/test-dev'
            git(repo,'checkout','-b',branch)
            atomic_json(repo/'chapter5/expanded_dev/launch.json',{'source_commit':source,'registration_sha256':'test'})
            git(repo,'add','.');git(repo,'commit','-m','activate');git(repo,'push','origin',branch)
            cfg={'protocol':'test','activation_branch':branch,'max_execution_slots':3}
            with patch('chapter5.expanded_dev.archive.verify_registration',return_value={'registration_sha256':'test'}):
                reserve(repo,state,cfg,branch,'1','1',1)
                self.assertTrue((repo/'chapter5/expanded_dev/runs/test/session.json').exists())
                with self.assertRaisesRegex(ValueError,'uncertain'):
                    reserve(repo,tmp/'bad',cfg,branch,'1','1',2)
                atomic_json(state/'status.json',{'phase':'continuation_needed'})
                (state/'checkpoint-evidence.txt').write_text('never reset')
                close(repo,state,cfg,branch,'1','1',1,True)
                saved=repo/'chapter5/expanded_dev/runs/test'
                self.assertEqual(json.loads((saved/'session.json').read_text())['status'],'closed')
                with self.assertRaisesRegex(ValueError,'new workflow attempt'):
                    reserve(repo,tmp/'new-attempt',cfg,branch,'2','1',2)
                next_state=tmp/'next';reserve(repo,next_state,cfg,branch,'1','1',2)
                self.assertEqual((next_state/'checkpoint-evidence.txt').read_text(),'never reset')
                atomic_json(next_state/'status.json',{'phase':'development_complete'})
                close(repo,next_state,cfg,branch,'1','1',2,True)
                with self.assertRaisesRegex(ValueError,'continuation'):
                    reserve(repo,tmp/'third',cfg,branch,'1','1',3)
                with self.assertRaisesRegex(ValueError,'slot budget'):
                    reserve(repo,tmp/'fourth',cfg,branch,'1','1',4)
                part=next(saved.glob('state.part-*'));part.write_bytes(part.read_bytes()+b'bad')
                from chapter5.archive import restore_state
                with self.assertRaisesRegex(ValueError,'integrity'):
                    restore_state(saved,tmp/'corrupt')

if __name__=='__main__':unittest.main()
