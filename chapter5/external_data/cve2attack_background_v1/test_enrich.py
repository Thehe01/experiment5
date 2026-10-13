import copy
import json
import unittest
import tempfile
from pathlib import Path
from unittest import mock
from enrich import parse_response, cpe_family, enrich_record, classify

ID = 'CVE-2021-1234'
GOOD = 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*'
CANDIDATE = {'id': ID, 'description': 'Original text', 'techniques': ['T1190'],
             'label_scope': ['T1190'], 'role': 'unassigned_external_development_candidate',
             'cpes': [], 'cwes': [], 'graph_ready': False,
             'missing_labels_are_confirmed_negatives': False}
PROV = {'response_file': 'raw.json', 'response_sha256': 'a'*64, 'url': 'https://services.nvd.nist.gov/test', 'fetched_at': '2026-10-11T00:00:00Z'}

def record():
    return {'id': ID, 'vulnStatus': 'Analyzed', 'published': '2021-01-01',
            'lastModified': '2026-01-01',
            'weaknesses': [{'source': 'nvd@nist.gov', 'type': 'Primary',
                            'description': [{'lang': 'en', 'value': 'CWE-79'}]}],
            'configurations': [{'nodes': [{'operator': 'OR', 'cpeMatch': [
                {'vulnerable': True, 'criteria': GOOD, 'versionEndExcluding': '1.2'},
                {'vulnerable': False, 'criteria': 'cpe:2.3:o:vendor:os:*:*:*:*:*:*:*:*'}]}]}]}

def response(items):
    return json.dumps({'format':'NVD_CVE','version':'2.0','totalResults':len(items),
                       'resultsPerPage':len(items),'startIndex':0,
                       'vulnerabilities':[{'cve':v} for v in items]}).encode()

class EnrichmentTests(unittest.TestCase):
    def test_batch_exact_ids(self):
        self.assertEqual(set(parse_response(response([record()]), [ID])), {ID})

    def test_batch_absent_not_error(self):
        self.assertEqual(parse_response(response([]), [ID]), {})

    def test_unexpected_id_rejected(self):
        r=record(); r['id']='CVE-2021-9999'
        with self.assertRaises(ValueError): parse_response(response([r]), [ID])

    def test_duplicate_result_rejected(self):
        with self.assertRaises(ValueError): parse_response(response([record(),record()]), [ID])

    def test_truncated_batch_rejected(self):
        r=json.loads(response([record()]));r['totalResults']=2
        with self.assertRaises(ValueError): parse_response(json.dumps(r).encode(), [ID])

    def test_wrong_format_rejected(self):
        with self.assertRaises(ValueError): parse_response(b'{"vulnerabilities": []}', [ID])

    def test_product_family_version_removed(self):
        self.assertEqual(cpe_family(GOOD), 'cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*')

    def test_escaped_colon_family(self):
        self.assertEqual(cpe_family(r'cpe:2.3:a:ven\:dor:prod:*:*:*:*:*:*:*:*'),
                         r'cpe:2.3:a:ven\:dor:prod:*:*:*:*:*:*:*:*')

    def test_unknown_vendor_and_short_cpe_rejected(self):
        self.assertIsNone(cpe_family('cpe:2.3:a:*:product:*:*:*:*:*:*:*:*'))
        self.assertIsNone(cpe_family('cpe:2.3:a:vendor:product:1.0'))

    def test_background_and_original_preserved(self):
        c=copy.deepcopy(CANDIDATE);e=enrich_record(c,record(),PROV)
        self.assertEqual(e['cwe_ids'], ['CWE-79'])
        self.assertEqual(e['cpe_families'], ['cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*'])
        for k in ['description','techniques','label_scope','role','missing_labels_are_confirmed_negatives']:
            self.assertEqual(e[k],c[k])
        self.assertEqual(c,CANDIDATE)
        self.assertTrue(e['graph_ready'])

    def test_environment_not_background(self):
        e=enrich_record(CANDIDATE,record(),PROV)
        self.assertEqual(e['cpes'], [GOOD])
        self.assertEqual(len(e['cpe_evidence']),1)
        self.assertEqual(e['cpe_evidence'][0]['match']['versionEndExcluding'],'1.2')
        self.assertEqual(e['environment_cpe_count'],1)

    def test_nested_configuration_tree(self):
        r=record();node=r['configurations'][0]['nodes'][0]
        r['configurations']=[{'operator':'AND','negate':False,'nodes':[{'children':[node]}]}]
        e=enrich_record(CANDIDATE,r,PROV)
        self.assertEqual(e['cpes'],[GOOD]);self.assertEqual(e['cpe_evidence'][0]['path'], '/configurations/0/nodes/0/children/0/cpeMatch/0')
        self.assertEqual(e['nvd_configurations'],r['configurations'])

    def test_placeholder_not_numeric_cwe(self):
        r=record();r['configurations']=[];r['weaknesses'][0]['description']=[{'value':'NVD-CWE-noinfo'},{'value':'CWE-0'},{'value':'CWE-79 extra text'}]
        e=enrich_record(CANDIDATE,r,PROV)
        self.assertFalse(e['graph_ready']);self.assertEqual(e['cwe_ids'],[])
        self.assertEqual(len(e['unparsed_cwes']),3)

    def test_cwe_alone_and_multisource_retained(self):
        r=record();r['configurations']=[];r['weaknesses'].append({'source':'cna','type':'Secondary','description':[{'value':'CWE-89'}]})
        e=enrich_record(CANDIDATE,r,PROV)
        self.assertTrue(e['graph_ready']);self.assertEqual(e['cwe_ids'],['CWE-79','CWE-89'])
        self.assertTrue(e['cwe_source_disagreement']);self.assertEqual(len(e['cwe_evidence']),2)

    def test_cpe_alone_satisfies_or_rule(self):
        r=record();r['weaknesses']=[]
        self.assertTrue(enrich_record(CANDIDATE,r,PROV)['graph_ready'])

    def test_rejected_record_quarantined(self):
        r=record();r['vulnStatus']='Rejected'
        e=classify(CANDIDATE,r,PROV)
        self.assertFalse(e['graph_ready']);self.assertEqual(e['metadata_status'],'rejected_source_record')

    def test_not_found_and_failed_distinguished(self):
        self.assertEqual(classify(CANDIDATE,None,PROV)['metadata_status'],'not_found')
        p=PROV|{'fetch_error':'TimeoutError'}
        self.assertEqual(classify(CANDIDATE,None,p)['metadata_status'],'fetch_failed')

    def test_wrong_id_enrichment_rejected(self):
        r=record();r['id']='CVE-2021-9999'
        with self.assertRaises(ValueError): enrich_record(CANDIDATE,r,PROV)

    def test_completed_snapshot_resume_is_immutable_and_no_network(self):
        import collect
        import hashlib
        raw=response([record()])
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);(p/'raw.json').write_bytes(raw)
            m={'candidate_sha256':collect.CANDIDATE_SHA,'completed_at':'fixed',
               'attempts':[], 'batches':[{'batch':0,'requested_ids':[ID],'status':'ok',
               'response_file':'raw.json','response_sha256':hashlib.sha256(raw).hexdigest()}]}
            before=json.dumps(m).encode();(p/'manifest.json').write_bytes(before)
            with mock.patch.object(collect,'read_candidates',return_value=[CANDIDATE]), \
                 mock.patch.object(collect.urllib.request,'urlopen',side_effect=AssertionError('Unexpected network')) as request:
                collect.collect('unused',p)
            request.assert_not_called()
            self.assertEqual((p/'manifest.json').read_bytes(),before)

if __name__=='__main__': unittest.main()
