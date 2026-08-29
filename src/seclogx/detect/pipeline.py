"""Maps Sigma's standard field taxonomy and logsource categories onto
seclogx's normalized schema.

Scope decision for v1: logsource categories are routed to their **Sysmon**
(channel, EventID) equivalents, not native Security-channel equivalents
(e.g. category `process_creation` routes to Sysmon EventID 1, not Security
EventID 4688). This is a deliberate, not incidental, scope call: most
practical Sigma rules for these categories are written against Sysmon's
field set (`Image`, `CommandLine`, `ParentImage`, ...) which mostly doesn't
exist on native Security events (4688 lacks CommandLine unless a
non-default GPO is enabled). See docs/known_limitations.md.

Field names not present in FIELD_MAPPING are left unmapped by
`FieldMappingTransformation` (pySigma leaves them as the original Sigma
field name), which will fail at DuckDB execution time with a clear
"column not found"-style error -- caught and reported per-rule by
detect/hunt.py, never silently ignored.
"""

from __future__ import annotations

from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation

# category -> (channel, event_id or [event_ids])
LOGSOURCE_ROUTES: dict[str, dict[str, object]] = {
    "process_creation": {"channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1},
    "network_connection": {"channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 3},
    "file_event": {"channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 11},
    "file_delete": {"channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 23},
    "registry_event": {"channel": "Microsoft-Windows-Sysmon/Operational", "EventID": [12, 13, 14]},
    "registry_add": {"channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 12},
    "registry_set": {"channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 13},
    "image_load": {"channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 7},
    "create_remote_thread": {"channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 8},
    "dns_query": {"channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 22},
    "pipe_created": {"channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 17},
    "ps_script": {"channel": "Microsoft-Windows-PowerShell/Operational", "EventID": 4104},
    "ps_module": {"channel": "Microsoft-Windows-PowerShell/Operational", "EventID": 4103},
    "process_access": {"channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 10},
}

# category -> table to hunt against. Every category above targets `events`
# (Windows Event Log); `webserver` is the one category routed to the
# `web_logs` table (IIS/nginx/Apache/Tomcat/Exchange-HttpProxy access logs)
# instead -- no channel/EventID condition applies there, so it deliberately
# has no entry in LOGSOURCE_ROUTES, only here.
LOGSOURCE_TABLE: dict[str, str] = {category: "events" for category in LOGSOURCE_ROUTES}
LOGSOURCE_TABLE["webserver"] = "web_logs"

# Sigma standard field name -> parenthesized SQL expression against our schema.
# Parenthesized so every leaf template ({field} LIKE ..., {field} = ..., ...)
# groups correctly regardless of DuckDB's ->/->> operator precedence
# (verified empirically -- an unparenthesized field expression can misparse
# against a following LIKE/AND and error at execution time).
FIELD_MAPPING: dict[str, str] = {
    # process_creation (Sysmon EventID 1)
    "Image": "(event_data ->> 'Image')",
    "OriginalFileName": "(event_data ->> 'OriginalFileName')",
    "CommandLine": "(event_data ->> 'CommandLine')",
    "CurrentDirectory": "(event_data ->> 'CurrentDirectory')",
    "ParentImage": "(event_data ->> 'ParentImage')",
    "ParentCommandLine": "(event_data ->> 'ParentCommandLine')",
    "User": "(event_data ->> 'User')",
    "IntegrityLevel": "(event_data ->> 'IntegrityLevel')",
    "Hashes": "(event_data ->> 'Hashes')",
    "md5": "(event_data ->> 'md5')",
    "sha1": "(event_data ->> 'sha1')",
    "sha256": "(event_data ->> 'sha256')",
    # network_connection (Sysmon EventID 3)
    "DestinationIp": "(event_data ->> 'DestinationIp')",
    "DestinationPort": "(event_data ->> 'DestinationPort')",
    "DestinationHostname": "(event_data ->> 'DestinationHostname')",
    "SourceIp": "(event_data ->> 'SourceIp')",
    "SourcePort": "(event_data ->> 'SourcePort')",
    "Protocol": "(event_data ->> 'Protocol')",
    "Initiated": "(event_data ->> 'Initiated')",
    "SourceIsIpv6": "(event_data ->> 'SourceIsIpv6')",
    "DestinationIsIpv6": "(event_data ->> 'DestinationIsIpv6')",
    # file_event / file_delete (Sysmon EventID 11 / 23)
    "TargetFilename": "(event_data ->> 'TargetFilename')",
    # registry_event (Sysmon EventID 12/13/14)
    "TargetObject": "(event_data ->> 'TargetObject')",
    "Details": "(event_data ->> 'Details')",
    "NewName": "(event_data ->> 'NewName')",
    # image_load (Sysmon EventID 7)
    "ImageLoaded": "(event_data ->> 'ImageLoaded')",
    "Signed": "(event_data ->> 'Signed')",
    "Signature": "(event_data ->> 'Signature')",
    "SignatureStatus": "(event_data ->> 'SignatureStatus')",
    # create_remote_thread (Sysmon EventID 8)
    "SourceImage": "(event_data ->> 'SourceImage')",
    "TargetImage": "(event_data ->> 'TargetImage')",
    "StartAddress": "(event_data ->> 'StartAddress')",
    "StartModule": "(event_data ->> 'StartModule')",
    "StartFunction": "(event_data ->> 'StartFunction')",
    # dns_query (Sysmon EventID 22)
    "QueryName": "(event_data ->> 'QueryName')",
    "QueryResults": "(event_data ->> 'QueryResults')",
    # pipe_created (Sysmon EventID 17/18)
    "PipeName": "(event_data ->> 'PipeName')",
    # process_access (Sysmon EventID 10)
    "SourceProcessId": "(event_data ->> 'SourceProcessId')",
    "TargetProcessId": "(event_data ->> 'TargetProcessId')",
    "GrantedAccess": "(event_data ->> 'GrantedAccess')",
    "CallTrace": "(event_data ->> 'CallTrace')",
    # PowerShell (EventID 4104 / 4103)
    "ScriptBlockText": "(event_data ->> 'ScriptBlockText')",
    "Payload": "(event_data ->> 'Payload')",
    # generic passthrough for the routing pseudo-fields (see LOGSOURCE_ROUTES)
    "EventID": "event_id",
    "channel": "channel",
    "Computer": "computer",
    # webserver (web_logs: IIS / nginx / Apache / Tomcat / Exchange HttpProxy),
    # field names matching the W3C literal names SigmaHQ's `webserver`-category
    # rules are written against.
    "c-ip": "client_ip",
    "cs-method": "method",
    "cs-uri-stem": "uri_stem",
    "cs-uri-query": "uri_query",
    "sc-status": "status",
    "cs-username": "username",
    "cs-useragent": "user_agent",
    "cs-referrer": "referer",
}


def seclogx_pipeline() -> ProcessingPipeline:
    items: list[ProcessingItem] = [
        ProcessingItem(
            transformation=AddConditionTransformation(conditions),
            rule_conditions=[LogsourceCondition(category=category)],
        )
        for category, conditions in LOGSOURCE_ROUTES.items()
    ]
    items.append(ProcessingItem(transformation=FieldMappingTransformation(FIELD_MAPPING)))
    return ProcessingPipeline(items=items, name="seclogx")
