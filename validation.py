"""Validation at pipeline and API boundaries. Missing evidence stays missing."""
import ipaddress
import math
import re

def number(value, name, low, high):
    if isinstance(value, bool):
        raise ValueError(f'{name} must be a number')
    try:
        result = float(value)
    except (TypeError, ValueError):
        raise ValueError(f'{name} must be a number') from None
    if not math.isfinite(result) or not low <= result <= high:
        raise ValueError(f'{name} must be between {low} and {high}')
    return result

def validate_asset(asset):
    if not isinstance(asset, dict):
        raise ValueError('Asset must be an object')
    result = dict(asset)
    try:
        ipaddress.ip_address(result.get('ip', ''))
    except ValueError:
        raise ValueError('Asset requires a valid IP address') from None
    port = number(result.get('port'), 'port', 1, 65535)
    if not port.is_integer():
        raise ValueError('port must be an integer')
    result['port'] = int(port)
    result['criticality'] = number(result.get('criticality', .5), 'criticality', 0, 1)
    for field in ('vendor','product','firmware','device_type','service','zone'):
        value = result.get(field)
        if value is not None and (not isinstance(value,str) or len(value)>255):
            raise ValueError(f'{field} must be text of at most 255 characters')
    if result.get('zone') not in (None,'OT','IT','DMZ','SCADA_Zone','Unknown'):
        raise ValueError('Unsupported asset zone')
    for field in ('packet_count','days_since_patch'):
        if result.get(field) is not None:
            value=number(result[field],field,0,1e12)
            if not value.is_integer():raise ValueError(f'{field} must be an integer')
            result[field]=int(value)
    for field in ('encrypted','firmware_eol'):
        if result.get(field) is not None and not isinstance(result[field],bool):
            raise ValueError(f'{field} must be true, false, or null')
    return result

def validate_cve(cve):
    if not isinstance(cve,dict) or not re.fullmatch(r'CVE-\d{4}-\d{4,}', str(cve.get('cve_id',''))):
        raise ValueError('Invalid CVE identifier')
    result=dict(cve)
    for field,high in (('cvss',10),('epss',1),('similarity',1),('risk_score',10)):
        if result.get(field) is not None:result[field]=number(result[field],field,0,high)
    if result.get('kev') not in (None,False,True,0,1):raise ValueError('kev must be boolean')
    if result.get('applicability') not in (None,'CONFIRMED','POTENTIAL','UNKNOWN','NOT_AFFECTED'):
        raise ValueError('Invalid applicability status')
    return result
