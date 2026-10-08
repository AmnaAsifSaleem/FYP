import sys
from pathlib import Path
import pandas as pd
import pytest
from sklearn.feature_extraction.text import TfidfVectorizer

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cve_applicability import evaluate, product_match
from cve_discovery import CandidateCorpus, assess_asset

ASSET = {'ip': '192.0.2.10', 'port': 502, 'zone': 'OT', 'vendor': 'Siemens',
         'product': 'S7-300', 'firmware': '3.2', 'criticality': .9,
         'identity_verified': True, 'firmware_verified': True}


def constraint(**changes):
    return {'vulnerable': True, 'simple_configuration': True, 'vendor': 'Siemens',
            'product': 'SIMATIC S7-300', 'version': '*',
            'versionStartIncluding': '3.0', 'versionEndExcluding': '3.3', **changes}


@pytest.mark.parametrize('vendor,a,b', [
    ('Siemens', 'S7-300', 'SIMATIC S7_300'),
    ('Siemens', 'S71200', 'SIMATIC S7-1200'),
    ('Siemens', 'WinCC OA', 'SIMATIC WinCC Open Architecture'),
    ('Schneider', 'Modicon M221', 'M221'),
    ('Cisco', 'ASA', 'Adaptive Security Appliance'),
    ('Cisco', 'ASA Firewall', 'Adaptive Security Appliance Software'),
    ('Dell', 'iDRAC8', 'EMC iDRAC8'),
    ('Dell', 'iDRAC8', 'Integrated Dell Remote Access Controller 8')])
def test_controlled_aliases(vendor, a, b):
    assert product_match(vendor, a, vendor, b) == 'alias'


@pytest.mark.parametrize('vendor,a,b', [
    ('Siemens', 'S7-300', 'S7-1200'), ('Dell', 'iDRAC8', 'iDRAC9'),
    ('Siemens', 'WinCC OA', 'WinCC'), ('Cisco', 'ASA', 'IOS XE'),
    ('Siemens', 'S7-300 CPU 315', 'S7-300 CPU 317')])
def test_wrong_models_rejected(vendor, a, b):
    assert product_match(vendor, a, vendor, b) is None


def test_vendor_mismatch_rejected():
    assert product_match('Siemens', 'S7-300', 'Other', 'S7-300') is None


def test_family_cannot_confirm_even_with_verified_firmware():
    r = {'cpe_matches': [constraint(product='SIMATIC S7-300 CPU 315')]}
    assert evaluate(ASSET, r)[0] == 'POTENTIAL'


@pytest.mark.parametrize('key,value,status', [
    ('versionEndIncluding', '3.2', 'CONFIRMED'),
    ('versionEndExcluding', '3.2', 'NOT_AFFECTED'),
    ('versionStartExcluding', '3.2', 'NOT_AFFECTED')])
def test_explicit_boundary_semantics(key, value, status):
    c = constraint(); c.pop('versionEndExcluding'); c[key] = value
    assert evaluate(ASSET, {'cpe_matches': [c]})[0] == status


@pytest.mark.parametrize('asset', [
    {**ASSET, 'firmware_verified': False}, {**ASSET, 'identity_verified': False},
    {**ASSET, 'firmware': 'Unknown'}, {**ASSET, 'firmware': '9.6(4)42'},
    {k: v for k, v in ASSET.items() if k != 'firmware_verified'}])
def test_unverified_or_unsupported_firmware_stays_potential(asset):
    assert evaluate(asset, {'cpe_matches': [constraint()]})[0] == 'POTENTIAL'


def test_unverified_firmware_cannot_exclude():
    assert evaluate({**ASSET, 'firmware': '4.0', 'firmware_verified': False},
                    {'cpe_matches': [constraint()]})[0] == 'POTENTIAL'


def test_all_cpe_alternatives_must_be_excluded():
    assert evaluate(ASSET, {'cpe_matches': [constraint(versionEndExcluding='3.1'),
                                           constraint(simple_configuration=False)]})[0] == 'POTENTIAL'


@pytest.mark.parametrize('firmware,phrase', [('3.3', 'boundary'), ('4.0', 'outside'),
                                           ('3.2', 'consistent'), ('Unknown', 'missing')])
def test_legacy_firmware_comparison_is_advisory(firmware, phrase):
    status, reason = evaluate({**ASSET, 'firmware': firmware},
                             {'vendor': 'Siemens', 'product': 'SIMATIC S7-300',
                              'version_start': '3.0', 'version_end': '3.3'})
    assert status == 'POTENTIAL' and phrase in reason


def test_cpe_product_overrides_flattened_product():
    assert evaluate(ASSET, {'vendor': 'Siemens', 'product': 'S7-300',
                           'cpe_matches': [constraint(product='S7-1200')]})[0] == 'UNKNOWN'


def test_missing_numeric_bound_is_not_printed_as_nan():
    status, reason = evaluate(ASSET, {'vendor': 'Siemens', 'product': 'S7-300',
                                     'version_start': float('nan'), 'version_end': '3.3'})
    assert status == 'POTENTIAL' and 'nan' not in reason
    assert 'consistent' in reason


def corpus(name, products):
    rows = [{'cve_id': f'CVE-2020-{i+1000}', 'vendor': vendor, 'product': product,
             'cvss': 7, 'epss': .1, 'kev': 0, 'description': 'Unrelated text',
             'version_start': '', 'version_end': ''}
            for i, (vendor, product) in enumerate(products)]
    vectorizer = TfidfVectorizer().fit(['Unrelated text'])
    return CandidateCorpus(name, (vectorizer, vectorizer.transform(['Unrelated text'] * len(rows)), pd.DataFrame(rows)))


def test_name_lookup_bypasses_zero_similarity_and_general_supplements_ot():
    ot = corpus('OT', [('Siemens', 'SIMATIC S7-300')])
    general = corpus('GENERAL', [('Siemens', 'SIMATIC S7-300'), ('Siemens', 'S7-300 CPU 315')])
    result = assess_asset(ASSET, [ot, general])
    assert len(result['cves']) == 2
    assert result['cves'][0]['similarity'] == 0
    assert all(c['applicability'] == 'POTENTIAL' for c in result['cves'])


def test_new_asset_uses_general_without_inventory_changes():
    result = assess_asset({**ASSET, 'vendor': 'Cisco', 'product': 'ASA'},
                          [corpus('OT', [('Siemens', 'S7-300')]),
                           corpus('GENERAL', [('Cisco', 'Adaptive Security Appliance')])])
    assert len(result['cves']) == 1 and result['cves'][0]['corpus'] == 'GENERAL'


def test_no_matches_does_not_mean_safe():
    result = assess_asset({**ASSET, 'product': 'Unknown'}, [corpus('OT', [('Siemens', 'S7-300')])])
    assert not result['cves'] and result['assessment'] == 'UNKNOWN'
