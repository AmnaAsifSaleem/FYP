"""Project parameters, not numerical NIST/NERC requirements.
Criticalities are testbed assumptions requiring plant consequence review.
CVSS CR/IR/AR default to Not Defined, not inferred from device type.
"""
import os
from validation import number
POLICY_VERSION='testbed-priority-1'
CRITICALITY_FLOOR=.5
EPSS_MAX_POINTS=.75
KEV_POINTS=.75
IDS_MAX_POINTS=1.5
ANOMALY_MAX_POINTS=1.
IDS_WEIGHTED_EVENT_CAPACITY=30.
IDS_SEVERITY_WEIGHT={1:1.,2:.6,3:0.}
ALERT_WINDOW_SECONDS=number(os.environ.get('CAVE_OT_ALERT_WINDOW_SECONDS','300'),'alert window',1,86400)
ALERT_LOG_TIMEZONE=os.environ.get('CAVE_OT_ALERT_LOG_TIMEZONE','UTC')
CVSS_REQUIREMENTS={key:os.environ.get('CAVE_OT_CVSS_'+key,'X') for key in ('CR','IR','AR')}
if any(v not in ('X','L','M','H') for v in CVSS_REQUIREMENTS.values()):
    raise ValueError('CAVE_OT_CVSS_CR/IR/AR must be X, L, M or H')
