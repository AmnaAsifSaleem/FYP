"""Deterministic plant policy checks. Standards references are rationale,
not a claim of complete NIST/NERC certification. Unknown evidence never passes.
"""
from validation import validate_asset,validate_cve,number

DEFAULT_RULES=[
 {'rule_name':'OT Zone Encryption','zone':'OT','encrypted':True},
 {'rule_name':'SCADA Zone Protocol Restriction','zone':'SCADA_Zone'},
 {'rule_name':'IT Zone HTTPS Only','zone':'IT','service':'HTTP','encrypted':True},
 {'rule_name':'IT Zone OT Protocol Restriction','zone':'IT'},
 {'rule_name':'DMZ Zone Segmentation','zone':'DMZ'},
 {'rule_name':'Patch Compliance','days_since_patch_threshold':35},
 {'rule_name':'Firmware EOL Check'},
 {'rule_name':'High CVSS Alert','cvss_threshold':7},
]
INSECURE={'modbus','s7comm','dnp3','bacnet','http','telnet','ftp','ipmi','snmp_v1','snmp_v2'}
SUPPORTED={r['rule_name'] for r in DEFAULT_RULES}

def evaluate(asset,cves,rules,ml_signal=None):
    errors=[]
    try:asset=validate_asset(asset)
    except ValueError as e:errors.append(str(e))
    valid=[]
    for cve in cves:
        try:valid.append(validate_cve(cve))
        except ValueError as e:errors.append(str(e))
    checks=[]
    for rule in rules:
        name=rule.get('rule_name','Unnamed rule')
        status='PASS';reason='Observed evidence satisfies this plant rule.'
        action='No action required.'
        if errors:
            status='UNKNOWN';reason='Invalid input: '+ '; '.join(errors)
        elif name not in SUPPORTED:
            status='UNKNOWN';reason='Unsupported rule; an evaluator must be configured.'
        elif rule.get('zone') and asset.get('zone') not in (rule['zone'],None,'Unknown'):
            status='NOT_APPLICABLE';reason='Asset is outside this rule scope.'
        elif rule.get('zone') and asset.get('zone') in (None,'Unknown'):
            status='UNKNOWN';reason='Zone has not been established.'
        elif rule.get('device_type') and asset.get('device_type')!=rule['device_type']:
            status='UNKNOWN' if asset.get('device_type') in (None,'Unknown') else 'NOT_APPLICABLE'
            reason='Device type does not establish applicability.'
        elif rule.get('port') is not None and asset['port']!=rule['port']:
            status='NOT_APPLICABLE';reason='Port is outside this rule scope.'
        elif rule.get('service') and (asset.get('service') or '').casefold()!=rule['service'].casefold():
            status='UNKNOWN' if asset.get('service') in (None,'Unknown') else 'NOT_APPLICABLE'
            reason='Service is outside this rule scope or unknown.'
        elif name in ('OT Zone Encryption','IT Zone HTTPS Only'):
            if asset.get('encrypted') is None:
                status='UNKNOWN';reason='Encryption has not been verified.'
            elif asset['encrypted'] is False:
                status='FAIL';reason='Observed transport does not meet encryption requirement.'
            action='Review supported secure transport or approved compensating segmentation; schedule OT changes.'
        elif name in ('SCADA Zone Protocol Restriction','DMZ Zone Segmentation','IT Zone OT Protocol Restriction'):
            service=(asset.get('service') or '').casefold()
            if not service or service=='unknown':status='UNKNOWN';reason='Protocol evidence missing.'
            elif service in INSECURE and (name.startswith('SCADA') or service in {'modbus','s7comm','dnp3','bacnet'}):
                status='FAIL';reason='Plant rule prohibits this protocol in this zone.'
            action='Review directional firewall rules and approved zone placement; do not disconnect process devices automatically.'
        elif name=='Patch Compliance':
            days=asset.get('days_since_patch');limit=rule.get('days_since_patch_threshold')
            if days is None:status='UNKNOWN';reason='Verified patch date is missing.'
            else:
                try:limit=number(35 if limit is None else limit,'patch threshold',0,1e6)
                except ValueError as e:status='UNKNOWN';reason=str(e)
                if status=='PASS' and days>limit:status='FAIL';reason=f'Patch age {days} days exceeds plant threshold {limit:g}.'
            action='Verify applicable patches and plan a tested maintenance window.'
        elif name=='Firmware EOL Check':
            if asset.get('firmware_eol') is None:status='UNKNOWN';reason='Vendor-supported lifecycle evidence is missing.'
            elif asset['firmware_eol']:status='FAIL';reason='Vendor lifecycle evidence identifies end-of-life firmware.'
            action='Obtain vendor lifecycle evidence and plan a supported upgrade or compensating controls.'
        elif name=='High CVSS Alert':
            try:limit=number(7 if rule.get('cvss_threshold') is None else rule['cvss_threshold'],'CVSS threshold',0,10)
            except ValueError as e:status='UNKNOWN';reason=str(e);limit=7
            confirmed=[c for c in valid if c.get('applicability')=='CONFIRMED']
            if status=='PASS':
                if any(c.get('cvss') is not None and c['cvss']>=limit for c in confirmed):
                    status='FAIL';reason=f'Confirmed applicable vulnerability meets CVSS threshold {limit:g}.'
                elif any(c.get('applicability')!='CONFIRMED' or c.get('cvss') is None for c in valid) or not asset.get('cve_assessment_complete'):
                    status='UNKNOWN';reason='CVE applicability or severity assessment is incomplete.'
            action='Validate candidate applicability, then prioritize confirmed severe vulnerabilities.'
        checks.append({'rule_name':name,'status':status,'reason':reason,'action':action,'policy_source':rule.get('policy_source','Plant policy'),'severity':'HIGH' if status=='FAIL' else 'INFO'})
    applicable=[r for r in checks if r['status']!='NOT_APPLICABLE']
    failed=[r for r in applicable if r['status']=='FAIL'];unknown=[r for r in applicable if r['status']=='UNKNOWN']
    if not applicable:unknown=[{'reason':'No evaluable active rules.'}]
    restrictions=any(r['rule_name'] in ('OT Zone Encryption','IT Zone HTTPS Only','SCADA Zone Protocol Restriction','DMZ Zone Segmentation','IT Zone OT Protocol Restriction') for r in failed)
    decision='RESTRICT' if restrictions else ('REMEDIATE' if failed else ('NEEDS_REVIEW' if unknown or errors else 'APPROVE'))
    status='NON_COMPLIANT' if failed else ('NEEDS_REVIEW' if unknown or errors else 'COMPLIANT')
    assessed=sum(r['status'] in ('PASS','FAIL') for r in applicable)
    passed=sum(r['status']=='PASS' for r in applicable)
    priority='URGENT' if failed and not errors and asset.get('criticality',0)>=.9 else ('HIGH' if failed else ('REVIEW' if unknown or errors else 'ROUTINE'))
    return {'compliance_status':status,'decision':decision,'compliance_score':passed/len(applicable) if applicable else 0,
            'confidence':assessed/len(applicable) if applicable else 0,'coverage':assessed/len(applicable) if applicable else 0,
            'explanation':'; '.join(r['reason'] for r in applicable if r['status']!='PASS') or 'All applicable plant checks passed.',
            'checks':checks,'validation_errors':errors,'ml_signal':ml_signal,'enforcement':'ADVISORY','priority':priority}
