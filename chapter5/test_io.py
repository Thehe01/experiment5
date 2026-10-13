import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from chapter5.io import atomic_json, download, read_json


class DownloadTests(unittest.TestCase):
    def test_receipted_temporary_bytes_are_recovered_without_new_request(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'source.json'; body=b'{"value":1}'
            path.with_name(path.name+'.tmp').write_bytes(body)
            atomic_json(path.with_name(path.name+'.receipt.json'),{'url':'https://example.org/source','sha256':hashlib.sha256(body).hexdigest()})
            atomic_json(path.with_name(path.name+'.request-state.json'),{'url':'https://example.org/source','attempts':3})
            with patch('urllib.request.urlopen',side_effect=AssertionError('unexpected request')):
                actual,receipt=download('https://example.org/source',path,{'download_attempts':3,'request_timeout_seconds':1})
            self.assertEqual(actual.read_bytes(),body)

    def test_failed_attempts_do_not_reset_on_resume(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'source.json';cfg={'download_attempts':2,'request_timeout_seconds':1}
            with patch('urllib.request.urlopen',side_effect=OSError('offline')) as request,patch('time.sleep'):
                for _ in range(2):
                    with self.assertRaises(RuntimeError):
                        download('https://example.org/source',path,cfg)
            self.assertEqual(request.call_count,2)
            self.assertEqual(read_json(path.with_name(path.name+'.request-state.json'))['attempts'],2)


if __name__=='__main__':
    unittest.main()
