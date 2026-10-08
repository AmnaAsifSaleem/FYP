"""Product recognition and evidence-based firmware applicability.

Legacy flattened bounds are advisory: they cannot establish applicability.
"""
import json
import re

ALIASES = {'schneider': 'schneider electric', 'ge': 'general electric',
           'rockwell automation': 'rockwell', 'allen bradley': 'rockwell',
           'dell emc': 'dell', 'dellemc': 'dell', 'cisco systems': 'cisco'}


def identity(text):
    s = re.sub(r'[^a-z0-9]+', ' ', str(text or '').casefold()).strip()
    return ALIASES.get(s, s)


def known(text):
    return identity(text) not in ('', 'unknown', 'nan', 'none')


def product_identity(vendor, product):
    """Vendor-scoped aliases; never remove model numbers or arbitrary words."""
    vendor, name = identity(vendor), identity(product)
    if vendor == 'siemens':
        name = re.sub(r'^simatic\s+', '', name)
        name = re.sub(r'\bs7\s*(\d+)\b', r's7 \1', name)
        name = re.sub(r'\bwincc\s+open\s+architecture\b', 'wincc oa', name)
    elif vendor == 'schneider electric':
        name = re.sub(r'^modicon\s+', '', name)
        name = re.sub(r'\bm\s+(\d+)\b', r'm\1', name)
    elif vendor == 'cisco':
        name = re.sub(r'\badaptive security appliance(?: software)?\b', 'asa', name)
        name = re.sub(r'^cisco\s+', '', name)
        if name in ('asa software', 'asa firewall'):
            name = 'asa'
    elif vendor == 'dell':
        name = re.sub(r'^(?:dell\s+)?emc\s+', '', name)
        name = re.sub(r'\bintegrated dell remote access controller\b', 'idrac', name)
        name = re.sub(r'\bidrac\s*(\d+)\b', r'idrac \1', name)
    return name


def product_match(asset_vendor, asset_product, record_vendor, record_product):
    if not all(known(x) for x in (asset_vendor, asset_product, record_vendor, record_product)):
        return None
    if identity(asset_vendor) != identity(record_vendor):
        return None
    a = product_identity(asset_vendor, asset_product)
    b = product_identity(record_vendor, record_product)
    if a == b:
        return 'exact' if identity(asset_product) == identity(record_product) else 'alias'
    # CPU submodels imply only family-level candidates, never exact-device proof.
    if identity(asset_vendor) == 'siemens':
        fa = re.match(r'^(s7 \d+)(?:$| cpu\b)', a)
        fb = re.match(r'^(s7 \d+)(?:$| cpu\b)', b)
        if fa and fb and fa[1] == fb[1]:
            # Two explicitly different CPU submodels are not interchangeable.
            if a == fa[1] or b == fb[1]:
                return 'family'
    if identity(asset_vendor) == 'dell':
        if a == 'idrac' and re.fullmatch(r'idrac \d+', b) or b == 'idrac' and re.fullmatch(r'idrac \d+', a):
            return 'family'
    return None


def version(value):
    value = str(value or '').strip().lstrip('vV')
    if not re.fullmatch(r'\d+(?:\.\d+)*', value):
        return None
    return tuple(map(int, value.split('.')))


def compare(a, b):
    x, y = version(a), version(b)
    if x is None or y is None:
        raise ValueError('Unsupported firmware version format')
    n = max(len(x), len(y))
    x += (0,) * (n - len(x))
    y += (0,) * (n - len(y))
    return (x > y) - (x < y)


def _firmware_note(asset):
    firmware = asset.get('firmware') or 'Unknown'
    source = asset.get('firmware_source') or asset.get('identity_source') or 'unspecified'
    verified = asset.get('firmware_verified') is True
    return f'Firmware {firmware} (source: {source}; {"verified" if verified else "unverified"}). '


def evaluate(asset, row):
    if not known(asset.get('vendor')) or not known(asset.get('product')):
        return 'UNKNOWN', 'Asset identity is incomplete.'
    raw = row.get('cpe_matches')
    try:
        matches = json.loads(raw) if isinstance(raw, str) else raw
    except (ValueError, TypeError):
        matches = None
    if not isinstance(matches, list):
        matches = []
    firmware = asset.get('firmware')
    verified = asset.get('identity_verified') is True and asset.get('firmware_verified') is True
    potential = outside = unresolved = False
    for match in matches:
        if not isinstance(match, dict) or match.get('vulnerable') is not True:
            continue
        kind = product_match(asset['vendor'], asset['product'], match.get('vendor'), match.get('product'))
        if not kind:
            continue
        potential = True
        if kind == 'family' or match.get('simple_configuration') is not True:
            unresolved = True
            continue
        try:
            if version(firmware) is None:
                unresolved = True
                continue
            checks = []
            exact = match.get('version')
            if exact not in (None, '', '*', '-'):
                checks.append(compare(firmware, exact) == 0)
            for key, op in (('versionStartIncluding', lambda x: x >= 0),
                            ('versionStartExcluding', lambda x: x > 0),
                            ('versionEndIncluding', lambda x: x <= 0),
                            ('versionEndExcluding', lambda x: x < 0)):
                if match.get(key):
                    checks.append(op(compare(firmware, match[key])))
            if not checks:
                unresolved = True
                continue
            if all(checks):
                return ('CONFIRMED' if verified else 'POTENTIAL', _firmware_note(asset) +
                        f'{kind.title()} product match; firmware satisfies preserved CPE constraints.' +
                        ('' if verified else ' Verify product identity and firmware before confirmation.'))
            outside = True
        except ValueError:
            unresolved = True
    if potential:
        if outside and not unresolved and verified:
            return 'NOT_AFFECTED', _firmware_note(asset) + 'Firmware is outside every preserved matching constraint.'
        return 'POTENTIAL', _firmware_note(asset) + 'Matching product found; constraints, model or firmware evidence require review.'
    # Preserved CPE records take precedence over a flattened primary product.
    if matches:
        return 'UNKNOWN', 'No matching vulnerable product in preserved CPE records.'
    kind = product_match(asset['vendor'], asset['product'], row.get('vendor'), row.get('product'))
    if not kind:
        return 'UNKNOWN', 'Text similarity alone does not establish product applicability.'
    reason = _firmware_note(asset) + f'{kind.title()} product match: {row.get("product")}. '
    if kind == 'family':
        reason += 'Exact hardware/model requires verification. '
    start, end = row.get('version_start'), row.get('version_end')
    start = str(start or '').strip()
    end = str(end or '').strip()
    if not known(start):
        start = ''
    if not known(end):
        end = ''
    reason += f'Legacy range: {start or "unspecified"} to {end or "unspecified"}. '
    if version(firmware) is None:
        reason += 'Firmware is missing or uses an unsupported version format. '
    elif (start and version(start) is None) or (end and version(end) is None):
        reason += 'Stored range uses an unsupported version format. '
    elif start and end and compare(start, end) > 0:
        reason += 'Stored range is inconsistent. '
    elif (start and compare(firmware, start) < 0) or (end and compare(firmware, end) > 0):
        reason += 'Firmware appears outside the stored range; verify the original advisory before exclusion. '
    elif (start and compare(firmware, start) == 0) or (end and compare(firmware, end) == 0):
        reason += 'Firmware is at a boundary whose inclusion is unspecified. '
    elif start or end:
        reason += 'Firmware is consistent with the stored bounds. '
    reason += 'Flattened ranges lack complete conditions and cannot confirm or exclude applicability.'
    return 'POTENTIAL', reason
