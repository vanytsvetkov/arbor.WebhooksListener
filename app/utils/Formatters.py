from datetime import timedelta

from models.Arbor.Attributes import Alert, Mitigation


def format_value(size: int | float, vn: str, power=1e+3) -> str:
    n = 0
    power_labels = {0: f'{vn}', 1: f'k{vn}', 2: f'M{vn}', 3: f'G{vn}', 4: f'T{vn}', 5: f'P{vn}', 6: f'E{vn}'}
    while size > power:
        size /= power
        n += 1
    return f"{size:.1f} {power_labels[n]}"


def format_time(attributes: Alert.Attributes | Mitigation.Attributes) -> str:
    state = attributes.ongoing

    if type(attributes) == Mitigation.Attributes:
        start_time = attributes.start + timedelta(hours=3)
    else:
        start_time = attributes.start_time + timedelta(hours=3)

    if not state:
        if type(attributes) == Mitigation.Attributes:
            stop_time = attributes.stop + timedelta(hours=3)
        else:
            stop_time = attributes.stop_time + timedelta(hours=3)

        duration = stop_time.replace(microsecond=0) - start_time.replace(microsecond=0)
        times = f"{start_time:%b %-d %H:%M} - {stop_time:%H:%M} ({str(duration)[:-3]})"
    else:
        stop_time = "<b>Ongoing</b>"
        times = f"{start_time:%b %-d %H:%M} - {stop_time}"
    return times

