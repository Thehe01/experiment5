import unittest
from .recovery import reconcile

class RecoveryTests(unittest.TestCase):
    def test_saved_success_resolves_without_replay(self):
        receipt={'unit':'u','binding':'b','checkpoint_sha256':'c','score_sha256':'s','max_score_error':0.,'verification_forward':1,'abstained':[]}
        row={'status':'UNKNOWN','receipt_sha256':'r'};inventory={'unit':'u','binding':'b','checkpoint_sha256':'c','scores_sha256':'s'}
        self.assertEqual(reconcile(receipt,row,inventory,'r')['status'],'done')
        self.assertEqual(row['status'],'UNKNOWN')
        for key,value in [('max_score_error',0.1),('score_sha256','changed'),('verification_forward',2)]:
            bad=dict(receipt);bad[key]=value
            with self.assertRaises(ValueError):reconcile(bad,row,inventory,'r')
        with self.assertRaises(ValueError):reconcile(receipt,row,inventory,'wrong_hash')

if __name__=='__main__':unittest.main()
