import copy
import unittest
from . import helpers as h


class RecoveryTests(unittest.TestCase):
    def test_budget_and_unknown(self):
        ledger = {'budget': 1, 'actions': {'a': {'status': 'planned'}, 'b': {'status': 'planned'}}}
        self.assertTrue(h.reserve(ledger, 'a'))
        self.assertEqual(h.consumed(ledger), 1)
        with self.assertRaises(ValueError): h.reserve(ledger, 'a')
        with self.assertRaises(ValueError): h.reserve(ledger, 'b')
        ledger['actions']['a']['status'] = 'UNKNOWN'
        with self.assertRaises(ValueError): h.reserve(ledger, 'a')
        ledger['actions']['a']['status'] = 'done'
        self.assertFalse(h.reserve(ledger, 'a'))

    def test_unregistered_rejected(self):
        with self.assertRaises(ValueError): h.reserve({'budget': 2, 'actions': {}}, 'unregistered')

    def test_background_boundary(self):
        g = {'nodes': [{'id': x} for x in ('train', 'a', 'b', 'w1', 'w2', 'p1', 'p2', 't')], 'split': {'train': ['train'], 'dev': ['a', 'b']}, 'edges': [{'head': 'a', 'relation': 'has_reported_cwe', 'tail': 'w1'}, {'head': 'b', 'relation': 'has_reported_cwe', 'tail': 'w2'}, {'head': 'a', 'relation': 'has_reported_cpe', 'tail': 'p1'}, {'head': 'b', 'relation': 'has_reported_cpe', 'tail': 'p2'}, {'head': 'train', 'relation': 'has_reported_cwe', 'tail': 'w1'}, {'head': 'a', 'relation': 'potentially_associated_with', 'tail': 't'}]}
        before = copy.deepcopy(g)
        v = h.permute(g, {'a': 'b', 'b': 'a'}, 'cwe')
        self.assertEqual(g, before)
        self.assertEqual(v['nodes'], g['nodes'])
        self.assertEqual([e for e in v['edges'] if e['relation'] != 'has_reported_cwe' or e['head'] == 'train'], [e for e in g['edges'] if e['relation'] != 'has_reported_cwe' or e['head'] == 'train'])
        self.assertEqual({(e['head'], e['tail']) for e in v['edges'] if e['relation'] == 'has_reported_cwe'}, {('a', 'w2'), ('b', 'w1'), ('train', 'w1')})
        self.assertEqual(h.permute(g, {'a': 'b', 'b': 'a'}, 'original'), g)
        with self.assertRaises(ValueError): h.permute(g, {'a': 'a', 'b': 'b'}, 'joint')

    def test_shape_energy(self):
        p = h.shape({'a': {'x': 1., 'y': 2., 'z': 3.}, 'b': {'x': 11., 'y': 12., 'z': 13.}})
        self.assertAlmostEqual(p['shared_energy_fraction'], 1.)
        p = h.shape({'a': {'x': 1., 'y': 2., 'z': 3.}, 'b': {'x': 3., 'y': 2., 'z': 1.}})
        self.assertAlmostEqual(p['shared_energy_fraction'], 0.)
        with self.assertRaises(ValueError): h.shape({'a': {'x': float('nan'), 'y': 1.}})

    def test_cache_validation(self):
        cache = {'action': 'a', 'registration_sha256': 'r', 'scores': {'c': {'t1': 1., 't2': 2.}}}
        h.check_cache(cache, 'a', 'r', ['c'], ['t1', 't2'])
        with self.assertRaises(ValueError): h.check_cache(cache, 'b', 'r', ['c'], ['t1', 't2'])
        with self.assertRaises(ValueError): h.check_cache(cache, 'a', 'r', ['protected'], ['t1', 't2'])
        cache['scores']['c']['t1'] = float('inf')
        with self.assertRaises(ValueError): h.check_cache(cache, 'a', 'r', ['c'], ['t1', 't2'])


if __name__ == '__main__': unittest.main()
