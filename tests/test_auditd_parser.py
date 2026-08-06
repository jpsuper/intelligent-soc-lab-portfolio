import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agents/parser-agent/src"))

from auditd_parser import main, parse_auditd_log, parse_syslog_auditd_line  # noqa: E402

SYSCALL_EXECVE = (
    "2026-06-14T00:18:34+00:00 ubuntu-victim01 auditd type=SYSCALL "
    "msg=audit(1781396314.485:3389): arch=c000003e syscall=59 success=yes exit=0 "
    "ppid=34304 pid=35974 auid=1000 uid=1000 gid=1000 euid=1000 tty=pts0 ses=128 "
    'comm="bash" exe="/usr/bin/bash" key="isl_execve"#035ARCH=x86_64 SYSCALL=execve '
    'AUID="victim01" UID="victim01" GID="victim01" EUID="victim01"'
)
EXECVE = (
    "2026-06-14T00:18:34+00:00 ubuntu-victim01 auditd type=EXECVE "
    'msg=audit(1781396314.485:3389): argc=3 a0="bash" a1=2D63 a2=77686F616D69'
)
CWD = (
    "2026-06-14T00:18:34+00:00 ubuntu-victim01 auditd type=CWD "
    'msg=audit(1781396314.485:3389): cwd="/home/victim01"'
)
PATH_EXEC = (
    "2026-06-14T00:18:34+00:00 ubuntu-victim01 auditd type=PATH "
    'msg=audit(1781396314.485:3389): item=0 name="/usr/bin/bash" nametype=NORMAL '
    "mode=0100755 ouid=0 ogid=0"
)
PROCTITLE = (
    "2026-06-14T00:18:34+00:00 ubuntu-victim01 auditd type=PROCTITLE "
    "msg=audit(1781396314.485:3389): proctitle=62617368002D630077686F616D69"
)
SYSCALL_TMP = (
    "2026-06-14T00:19:01+00:00 ubuntu-victim01 auditd type=SYSCALL "
    "msg=audit(1781396341.123:3390): arch=c000003e syscall=257 success=yes exit=3 "
    "a2=241 ppid=35975 pid=35976 auid=1000 uid=1000 gid=1000 euid=1000 tty=pts0 ses=129 "
    'comm="bash" exe="/usr/bin/bash" key="isl_tmp_marker"#035SYSCALL=openat '
    'AUID="victim01" UID="victim01" GID="victim01" EUID="victim01"'
)
PATH_TMP = (
    "2026-06-14T00:19:01+00:00 ubuntu-victim01 auditd type=PATH "
    'msg=audit(1781396341.123:3390): item=1 name="/tmp/ai_soc_lab_scenario_007_marker.txt" '
    "nametype=NORMAL mode=0100644 ouid=1000 ogid=1000"
)
SYSCALL_OTHER = (
    "2026-06-14T00:20:01+00:00 ubuntu-victim01 auditd type=SYSCALL "
    "msg=audit(1781396401.000:3391): arch=c000003e syscall=59 success=yes pid=36000 "
    'auid=1000 uid=1000 gid=1000 euid=1000 comm="grep" exe="/usr/bin/grep" key="other_key"'
)


def write_log(tmp_path: Path, lines: list[str]) -> Path:
    log_path = tmp_path / "auditd.log"
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return log_path


def test_parse_syslog_prefix_record_type_and_audit_serial() -> None:
    record = parse_syslog_auditd_line(SYSCALL_EXECVE)

    assert record is not None
    assert record["collector_timestamp"] == "2026-06-14T00:18:34+00:00"
    assert record["host"] == "ubuntu-victim01"
    assert record["program"] == "auditd"
    assert record["record_type"] == "SYSCALL"
    assert record["audit_epoch_raw"] == "1781396314.485"
    assert record["audit_serial"] == "3389"


def test_grouping_merges_supported_record_types_and_normalizes_execve(tmp_path: Path) -> None:
    log_path = write_log(tmp_path, [SYSCALL_EXECVE, EXECVE, CWD, PATH_EXEC, PROCTITLE])

    events = parse_auditd_log(log_path)

    assert len(events) == 1
    event = events[0]
    assert event["source"] == "auditd"
    assert event["host"] == "ubuntu-victim01"
    assert event["audit_serial"] == "3389"
    assert event["record_types"] == ["SYSCALL", "EXECVE", "CWD", "PATH", "PROCTITLE"]
    assert event["raw_record_count"] == 5
    assert event["audit_key"] == "isl_execve"
    assert event["event_type"] == "process_exec"
    assert event["syscall"] == "execve"
    assert event["syscall_num"] == "59"
    assert event["success"] is True
    assert event["pid"] == 35974
    assert event["ppid"] == 34304
    assert event["session"] == "128"
    assert event["tty"] == "pts0"
    assert event["auid"] == "victim01"
    assert event["auid_num"] == "1000"
    assert event["uid"] == "victim01"
    assert event["gid"] == "victim01"
    assert event["euid"] == "victim01"
    assert event["comm"] == "bash"
    assert event["exe"] == "/usr/bin/bash"
    assert event["cwd"] == "/home/victim01"
    assert event["argv"] == ["bash", "-c", "whoami"]
    assert event["argv_raw"] == ["bash", "2D63", "77686F616D69"]
    assert event["proctitle"] == "bash -c whoami"
    assert event["file_path"] is None
    assert event["paths"] == [
        {
            "item": 0,
            "name": "/usr/bin/bash",
            "nametype": "NORMAL",
            "mode": "0100755",
            "ouid": "0",
            "ogid": "0",
        }
    ]


def test_tmp_marker_normalizes_as_file_write_and_deduplicates_raw_records(tmp_path: Path) -> None:
    log_path = write_log(tmp_path, [SYSCALL_TMP, PATH_TMP, PATH_TMP])

    events = parse_auditd_log(log_path)

    assert len(events) == 1
    event = events[0]
    assert event["audit_key"] == "isl_tmp_marker"
    assert event["event_type"] == "file_write"
    assert event["syscall"] == "openat"
    assert event["file_path"] == "/tmp/ai_soc_lab_scenario_007_marker.txt"
    assert event["file_action"] == "write_create_truncate"
    assert event["paths"][0]["nametype"] == "NORMAL"
    assert event["raw_record_count"] == 2


def test_openat_numeric_write_create_truncate_flags_normalize_as_file_write(
    tmp_path: Path,
) -> None:
    syscall = (
        "2026-06-14T00:22:01+00:00 ubuntu-victim01 auditd type=SYSCALL "
        "msg=audit(1781396521.000:3393): arch=c000003e syscall=257 success=yes "
        "a2=241 pid=36002 ppid=36001 auid=1000 uid=1000 gid=1000 euid=1000 "
        'comm="bash" exe="/usr/bin/bash" key="scenario009_audit_smoke"#035SYSCALL=openat '
        'AUID="victim01" UID="victim01" GID="victim01" EUID="victim01"'
    )
    parent_path = (
        "2026-06-14T00:22:01+00:00 ubuntu-victim01 auditd type=PATH "
        'msg=audit(1781396521.000:3393): item=0 name="/tmp/scenario009" '
        "nametype=PARENT mode=040755 ouid=1000 ogid=1000"
    )
    target_path = (
        "2026-06-14T00:22:01+00:00 ubuntu-victim01 auditd type=PATH "
        'msg=audit(1781396521.000:3393): item=1 name="/tmp/scenario009/archive.tar.gz" '
        "nametype=CREATE mode=0100640 ouid=1000 ogid=1000"
    )
    log_path = write_log(tmp_path, [syscall, parent_path, target_path])

    events = parse_auditd_log(log_path)

    assert len(events) == 1
    assert events[0]["audit_key"] == "scenario009_audit_smoke"
    assert events[0]["event_type"] == "file_write"
    assert events[0]["file_path"] == "/tmp/scenario009/archive.tar.gz"
    assert events[0]["file_action"] == "write_create_truncate"
    assert events[0]["paths"] == [
        {
            "item": 0,
            "name": "/tmp/scenario009",
            "nametype": "PARENT",
            "mode": "040755",
            "ouid": "1000",
            "ogid": "1000",
        },
        {
            "item": 1,
            "name": "/tmp/scenario009/archive.tar.gz",
            "nametype": "CREATE",
            "mode": "0100640",
            "ouid": "1000",
            "ogid": "1000",
        },
    ]


def test_openat_read_only_numeric_flags_do_not_become_file_write(tmp_path: Path) -> None:
    syscall = (
        "2026-06-14T00:22:31+00:00 ubuntu-victim01 auditd type=SYSCALL "
        "msg=audit(1781396551.000:3395): arch=c000003e syscall=257 success=yes "
        "a0=ffffff9c a1=559888340000 a2=0 "
        "pid=36004 ppid=36001 auid=1000 uid=1000 gid=1000 euid=1000 "
        'comm="cat" exe="/usr/bin/cat" key="scenario009_audit_smoke"#035SYSCALL=openat '
        'AUID="victim01" UID="victim01" GID="victim01" EUID="victim01"'
    )
    path = (
        "2026-06-14T00:22:31+00:00 ubuntu-victim01 auditd type=PATH "
        'msg=audit(1781396551.000:3395): item=0 name="/tmp/scenario009/archive.tar.gz" '
        "nametype=NORMAL mode=0100640 ouid=1000 ogid=1000"
    )
    log_path = write_log(tmp_path, [syscall, path])

    events = parse_auditd_log(log_path)

    assert len(events) == 1
    assert events[0]["success"] is True
    assert events[0]["event_type"] == "audit_event"
    assert events[0]["file_action"] is None
    assert events[0]["file_path"] is None


def test_failed_file_syscall_does_not_become_positive_file_write(tmp_path: Path) -> None:
    syscall = (
        "2026-06-14T00:23:01+00:00 ubuntu-victim01 auditd type=SYSCALL "
        "msg=audit(1781396581.000:3394): arch=c000003e syscall=263 success=no exit=-2 "
        "pid=36003 ppid=36001 auid=1000 uid=1000 gid=1000 euid=1000 "
        'comm="rm" exe="/usr/bin/rm" key="scenario009_audit_smoke"#035SYSCALL=unlinkat '
        'AUID="victim01" UID="victim01" GID="victim01" EUID="victim01"'
    )
    path = (
        "2026-06-14T00:23:01+00:00 ubuntu-victim01 auditd type=PATH "
        'msg=audit(1781396581.000:3394): item=0 name="/tmp/scenario009/missing.tmp" '
        "nametype=DELETE mode=0100644 ouid=1000 ogid=1000"
    )
    log_path = write_log(tmp_path, [syscall, path])

    events = parse_auditd_log(log_path)

    assert len(events) == 1
    assert events[0]["success"] is False
    assert events[0]["event_type"] == "audit_event"


def test_successful_unsupported_file_syscall_with_path_does_not_become_file_write(
    tmp_path: Path,
) -> None:
    syscall = (
        "2026-06-14T00:23:31+00:00 ubuntu-victim01 auditd type=SYSCALL "
        "msg=audit(1781396611.000:3397): arch=c000003e syscall=263 success=yes exit=0 "
        "pid=36007 ppid=36001 auid=1000 uid=1000 gid=1000 euid=1000 "
        'comm="rm" exe="/usr/bin/rm" key="scenario009_audit_smoke"#035SYSCALL=unlinkat '
        'AUID="victim01" UID="victim01" GID="victim01" EUID="victim01"'
    )
    path = (
        "2026-06-14T00:23:31+00:00 ubuntu-victim01 auditd type=PATH "
        'msg=audit(1781396611.000:3397): item=0 name="/tmp/scenario009/stale.tmp" '
        "nametype=DELETE mode=0100644 ouid=1000 ogid=1000"
    )
    log_path = write_log(tmp_path, [syscall, path])

    events = parse_auditd_log(log_path)

    assert len(events) == 1
    assert events[0]["success"] is True
    assert events[0]["syscall"] == "unlinkat"
    assert events[0]["event_type"] == "audit_event"
    assert events[0]["file_action"] is None
    assert events[0]["file_path"] is None


def test_same_host_and_serial_with_different_audit_epoch_remain_separate_groups(
    tmp_path: Path,
) -> None:
    first = (
        "2026-06-14T00:24:01+00:00 ubuntu-victim01 auditd type=SYSCALL "
        "msg=audit(1781396641.000:3396): arch=c000003e syscall=85 success=yes "
        "pid=36005 auid=1000 uid=1000 gid=1000 euid=1000 "
        'comm="tar" exe="/usr/bin/tar" key="scenario009_audit_smoke"#035SYSCALL=creat'
    )
    second = (
        "2026-06-14T00:24:02+00:00 ubuntu-victim01 auditd type=SYSCALL "
        "msg=audit(1781396642.000:3396): arch=c000003e syscall=85 success=yes "
        "pid=36006 auid=1000 uid=1000 gid=1000 euid=1000 "
        'comm="tar" exe="/usr/bin/tar" key="scenario009_audit_smoke"#035SYSCALL=creat'
    )
    first_path = (
        "2026-06-14T00:24:01+00:00 ubuntu-victim01 auditd type=PATH "
        'msg=audit(1781396641.000:3396): item=1 name="/tmp/scenario009/first.tar.gz" '
        "nametype=CREATE mode=0100640 ouid=1000 ogid=1000"
    )
    second_path = (
        "2026-06-14T00:24:02+00:00 ubuntu-victim01 auditd type=PATH "
        'msg=audit(1781396642.000:3396): item=1 name="/tmp/scenario009/second.tar.gz" '
        "nametype=CREATE mode=0100640 ouid=1000 ogid=1000"
    )
    log_path = write_log(tmp_path, [first, second, first_path, second_path])

    events = parse_auditd_log(log_path)

    assert len(events) == 2
    assert {event["audit_serial"] for event in events} == {"3396"}
    assert {event["audit_epoch_raw"] for event in events} == {
        "1781396641.000",
        "1781396642.000",
    }
    assert {event["file_path"] for event in events} == {
        "/tmp/scenario009/first.tar.gz",
        "/tmp/scenario009/second.tar.gz",
    }


def test_audit_key_prefix_filter_keeps_only_matching_events(tmp_path: Path) -> None:
    log_path = write_log(tmp_path, [SYSCALL_EXECVE, EXECVE, SYSCALL_OTHER])

    events = parse_auditd_log(log_path, audit_key_prefix="isl_")

    assert len(events) == 1
    assert events[0]["audit_key"] == "isl_execve"


def test_cli_writes_output_json_with_host_override_and_filter(tmp_path: Path) -> None:
    log_path = write_log(tmp_path, [SYSCALL_EXECVE, EXECVE, SYSCALL_OTHER])
    output_path = tmp_path / "nested" / "auditd_events.json"

    main(
        [
            "--input",
            str(log_path),
            "--host",
            "override-host",
            "--audit-key-prefix",
            "isl_",
            "--output",
            str(output_path),
        ]
    )

    events = json.loads(output_path.read_text(encoding="utf-8"))
    assert len(events) == 1
    assert events[0]["host"] == "override-host"
    assert events[0]["event_type"] == "process_exec"


def test_ssh_persistence_maps_only_when_path_matches(tmp_path: Path) -> None:
    syscall = (
        "2026-06-14T00:21:01+00:00 ubuntu-victim01 auditd type=SYSCALL "
        "msg=audit(1781396461.000:3392): arch=c000003e syscall=257 success=yes pid=36001 "
        'a2=241 auid=1000 uid=1000 gid=1000 euid=1000 comm="bash" exe="/usr/bin/bash" '
        'key="isl_ssh_persistence"#035SYSCALL=openat'
    )
    path = (
        "2026-06-14T00:21:01+00:00 ubuntu-victim01 auditd type=PATH "
        'msg=audit(1781396461.000:3392): item=1 name="/home/victim01/.ssh/authorized_keys" '
        "nametype=NORMAL mode=0100600 ouid=1000 ogid=1000"
    )
    log_path = write_log(tmp_path, [syscall, path])

    events = parse_auditd_log(log_path)

    assert events[0]["event_type"] == "persistence_file_change"
    assert events[0]["file_path"] == "/home/victim01/.ssh/authorized_keys"
