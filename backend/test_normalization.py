
from normalization.ocsf_normalization import normalize_event

test_events = [
    {
        "source_type": "endpoint",
        "event_type": "process_started",
        "hostname": "host-01",
        "process_name": "powershell.exe",
    },
    {
        "source_type": "network",
        "event_type": "connection",
        "source_ip": "192.168.1.10",
        "destination_ip": "10.0.0.5",
        "destination_port": 443,
    },
    {
        "source_type": "authentication",
        "event_type": "login_success",
        "username": "analyst",
        "hostname": "host-01",
    },
    {
        "source_type": "application",
        "event_type": "application_error",
        "hostname": "app-server-01",
        "severity": "medium",
    },
]

for event in test_events:
    result = normalize_event(event)

    assert result["metadata"]["source_type"] == event["source_type"]
    assert result["class_uid"] is not None
    assert result["unmapped"]["raw_event"] == event

    print(
        f"PASS: {event['source_type']} -> "
        f"{result['class_name']} "
        f"(class_uid={result['class_uid']})"
    )

print("\nAll four source smoke tests passed.")

