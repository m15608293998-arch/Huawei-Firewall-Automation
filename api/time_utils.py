from datetime import datetime, timedelta, timezone


CHINA_STANDARD_TIME = timezone(timedelta(hours=8))


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def to_china_time_iso(value: str | None) -> str | None:
    if value is None:
        return None

    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(CHINA_STANDARD_TIME).isoformat()
