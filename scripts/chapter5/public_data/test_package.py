import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
import pyarrow as pa
import pyarrow.parquet as pq
from chapter5.public_data.build import build, encode
from chapter5.public_data.verify import verify
from chapter5.public_data.test_adapter import old_graph, pattern, row


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        bundle={'objects':[pattern('T1190'),pattern('T1203')]}
        self.attack=self.root/'attack.json';self.attack.write_bytes(encode(bundle))
        g=old_graph();g['source_attack_sha256']=hashlib.sha256(self.attack.read_bytes()).hexdigest()
        self.graph=self.root/'v1.json';self.graph.write_bytes(encode(g))
        self.config={'parquet':{},'expected_source_rows':20,'split_seed':20261011,
                     'v1_graph_sha256':hashlib.sha256(self.graph.read_bytes()).hexdigest(),
                     'attack_sha256':g['source_attack_sha256']}
        for s,indices in [('train',range(14)),('test',range(14,20))]:
            rows=[]
            for i in indices:
                r=row(f'CVE-2020-{1000+i}',labels=['T1190']+(['T1203'] if i==0 else []))
                r.pop('public_split');rows.append(r)
            filename=s+'-00000-of-00001.parquet';path=self.root/filename
            pq.write_table(pa.Table.from_pylist(rows),path)
            self.config['parquet'][s]={'filename':filename,'rows':len(rows),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
        self.out=self.root/'package'

    def tearDown(self):
        self.temp.cleanup()

    def run_build(self, out=None):
        return build(self.root,self.graph,self.attack,out or self.out,self.config)

    def test_real_parquet_path_rebuild_and_zip_verify(self):
        receipt=self.run_build()
        second=self.run_build(self.root/'second')
        self.assertEqual(receipt['archive_sha256'],second['archive_sha256'])
        self.assertEqual(receipt['eligible_cves'],20)
        self.assertEqual(receipt['groups'],{'train':14,'dev':3,'reserved_holdout':3})
        self.assertEqual(verify(self.out),verify(self.out.with_suffix('.zip')))
        self.assertEqual(self.run_build(),receipt)

    def test_changed_source_fails_before_output(self):
        self.attack.write_bytes(self.attack.read_bytes()+b' ')
        with self.assertRaisesRegex(ValueError,'input digest'):
            self.run_build()
        self.assertFalse(self.out.exists())

    def test_tampered_output_is_rejected_without_overwrite(self):
        self.run_build()
        path=self.out/'audit.json';path.write_bytes(b'{}\n')
        with self.assertRaisesRegex(ValueError,'digest'):
            verify(self.out)
        with self.assertRaisesRegex(ValueError,'refuse overwrite'):
            self.run_build()
        self.assertEqual(path.read_bytes(),b'{}\n')

    def test_rehashed_held_labels_cannot_pass_logical_check(self):
        self.run_build()
        split=json.loads((self.out/'development-split.json').read_text())
        graph=json.loads((self.out/'graph.json').read_text())
        held=next(e for e in graph['edges'] if e['head'] in split['dev'] and e['relation']=='potentially_associated_with')
        p=self.out/'training-edges.json';edges=json.loads(p.read_text());edges.append(held);p.write_bytes(encode(edges))
        mpath=self.out/'manifest.json';m=json.loads(mpath.read_text())
        m['files'][p.name]={'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
        mpath.write_bytes(encode(m))
        with self.assertRaisesRegex(ValueError,'held labels'):
            verify(self.out)

    def test_unsafe_archive_member_is_rejected(self):
        bad=self.root/'bad.zip'
        with zipfile.ZipFile(bad,'w') as z:
            z.writestr('../outside.json','{}')
        with self.assertRaisesRegex(ValueError,'member names'):
            verify(bad)

    def test_rehashed_label_change_cannot_replace_expert_gold(self):
        self.run_build()
        p=self.out/'records.jsonl';records=[json.loads(x) for x in p.read_text().splitlines()]
        records[1]['source_techniques']=['T1203']
        p.write_bytes(b''.join(encode(r) for r in records))
        mpath=self.out/'manifest.json';m=json.loads(mpath.read_text())
        m['files'][p.name]={'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
        mpath.write_bytes(encode(m))
        with self.assertRaisesRegex(ValueError,'source lineage'):
            verify(self.out)


if __name__=='__main__':
    unittest.main()
