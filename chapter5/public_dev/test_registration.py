import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from chapter5.public_dev import campaign

class RegistrationTests(unittest.TestCase):
    def test_real_package_and_frozen_code_fold_tampering(self):
        repo=Path(__file__).resolve().parents[2]
        verification=campaign.verify_registration(repo)
        self.assertEqual(verification['training_units_registered'],36)
        self.assertEqual(verification['package']['candidate_techniques'],697)
        self.assertTrue(all(f['train_supervised_techniques']==174 for f in verification['folds']))
        with tempfile.TemporaryDirectory() as tmp:
            clone=Path(tmp)
            paths=set(campaign.source_files(repo))|{'chapter5/public_dev/registration.json','chapter5/public_dev/folds.json','chapter5/public_data/data/public-potential-v1.zip'}
            for path in paths:
                dest=clone/path;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(repo/path,dest)
            with patch.object(campaign,'ROOT',clone/'chapter5/public_dev'):
                self.assertEqual(campaign.verify_registration(clone),verification)
                code=clone/'chapter5/public_dev/model.py';original=code.read_bytes();code.write_bytes(original+b'\n# changed\n')
                with self.assertRaisesRegex(ValueError,'registration/code mismatch'):
                    campaign.verify_registration(clone)
                code.write_bytes(original)
                folds=clone/'chapter5/public_dev/folds.json';original=folds.read_bytes();folds.write_bytes(original+b' ')
                with self.assertRaisesRegex(ValueError,'registration/code mismatch'):
                    campaign.verify_registration(clone)
                folds.write_bytes(original)
                package=clone/'chapter5/public_data/data/public-potential-v1.zip';package.write_bytes(package.read_bytes()+b'changed')
                with self.assertRaisesRegex(ValueError,'package byte mismatch'):
                    campaign.verify_registration(clone)

if __name__=='__main__':unittest.main()
