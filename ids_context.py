"""Timestamped IDS evidence used in a finite recent scoring window."""
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
from risk_policy import ALERT_WINDOW_SECONDS,ALERT_LOG_TIMEZONE,IDS_SEVERITY_WEIGHT
from validation import number

def utc_time(value):
    if isinstance(value,str):value=datetime.fromisoformat(value.replace('Z','+00:00'))
    if not isinstance(value,datetime) or value.tzinfo is None:
        raise ValueError('IDS timestamps must include a time zone')
    return value.astimezone(timezone.utc)

def fast_timestamp(value,now=None):
    now=utc_time(now or datetime.now(timezone.utc))
    log_zone=timezone.utc if ALERT_LOG_TIMEZONE=='UTC' else ZoneInfo(ALERT_LOG_TIMEZONE)
    local_now=now.astimezone(log_zone)
    candidates=[]
    for year in (local_now.year-1,local_now.year,local_now.year+1):
        try:
            fmt='%m/%d/%Y-%H:%M:%S.%f' if '.' in value else '%m/%d/%Y-%H:%M:%S'
            if value.split('-')[0].count('/')==2:
                return datetime.strptime(value,fmt).replace(tzinfo=log_zone).astimezone(timezone.utc)
            dt=datetime.strptime(value.split('-')[0]+f'/{year}-'+value.split('-',1)[1],fmt)
            candidates.append(dt.replace(tzinfo=log_zone).astimezone(timezone.utc))
        except ValueError:continue
    if not candidates:raise ValueError('Invalid Suricata fast.log timestamp')
    return min(candidates,key=lambda dt:abs((dt-now).total_seconds()))

def recent_events(events,now=None,window_seconds=ALERT_WINDOW_SECONDS):
    now=utc_time(now or datetime.now(timezone.utc))
    window=number(window_seconds,'alert window',1,86400)
    result=[];seen=set()
    for event in events:
        try:
            stamp=utc_time(event['timestamp'])
            if not 0<=(now-stamp).total_seconds()<=window:continue
            key=tuple(event.get(k) for k in ('timestamp','signature_id','message','src_ip','src_port','dest_ip','dest_port','severity'))
            if key in seen:continue
            seen.add(key);result.append(event)
        except (KeyError,ValueError,TypeError):continue
    return result

def risk_context(events,now=None,window_seconds=ALERT_WINDOW_SECONDS):
    recent=recent_events(events,now,window_seconds)
    significant=[e for e in recent if e.get('severity') in (1,2)]
    return {'alert_events':recent,'risk_alert_count':len(significant),
            'risk_alert_severity':min((e['severity'] for e in significant),default=3),
            'risk_alert_weighted_count':sum(IDS_SEVERITY_WEIGHT[e['severity']] for e in significant),
            'alert_window_seconds':window_seconds,
            'context_generated_at':utc_time(now or datetime.now(timezone.utc)).isoformat()}
