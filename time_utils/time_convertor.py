from datetime import datetime, timezone

def datetime_to_string(dt_obj):
    """
    Converts a datetime object to a string representation in the format '%Y-%m-%dT%H:%MZ'.
    """  
    return dt_obj.strftime('%Y-%m-%dT%H:%MZ')


def string_to_datetime(date_str):
    """
    Converts a string representation of a date and time to a datetime object.
    """
    return datetime.strptime(date_str, '%Y-%m-%dT%H:%MZ')

def time_converter(api_timestamp) -> str:
    """
    Converts an API timestamp to a JSON feed timestamp.
    """
    api_datetime = datetime.strptime(api_timestamp, "%Y-%m-%dT%H:%M:%S.%f")
    json_feed_timestamp = api_datetime.strftime("%Y-%m-%dT%H:%MZ")
    return json_feed_timestamp

def convert_date_to_nvd_date_api2(date: datetime) -> str:
    """
    Returns a datetime string of NVD recognized date format
    """
    utc_date = date.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
    return f"{utc_date}"