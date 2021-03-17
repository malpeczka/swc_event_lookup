#! /usr/bin/env python3

"""

Querying SWC API - 2021, Nien Huei Chang

swc_event_lookup.py - main program

"""

import re
import sys
import json
import time
import requests


SWC_API_KEY = "swc_api_key.txt"
SWC_SESSION_URL = "https://cisco-maclemon.obsrvbl.com/api/v3/snapshots/session-data/"
SWC_ALERT_URL = "https://cisco-maclemon.obsrvbl.com/api/v3/alerts/alert/"
SWC_EVENT_FILE_NAME = "event.json"


def load_swc_key():
    """Load SWC API key from file."""

    try:
        with open(SWC_API_KEY, "r") as _:
            return _.readline().strip()

    except (IOError):
        print(f"\nError: Unable to read key from '{SWC_API_KEY}'...\n", file=sys.stderr)
        sys.exit(1)


def query_service(url, parameters):
    """Query service and return the response."""

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "ApiKey " + load_swc_key(),
    }

    try:
        response = requests.get(f"{url}", headers=headers, params=parameters)

    except requests.exceptions.ConnectionError:
        print(f"Error: Unable to connect to the service using '{url} url...\n", file=sys.stderr)
        sys.exit(3)

    if response.status_code != 200:
        print(f"Error: Received not OK status code '{response.status_code}' from the service...\n", file=sys.stderr)
        sys.exit(4)

    if "application/json" not in response.headers.get("Content-Type"):
        print(f"Error: Received not json formatted content '{response.headers.get('Content-Type')}' from the service...\n", file=sys.stderr)
        sys.exit(5)

    return response.json()["objects"]


def timestamp_range(timestamp, n):
    """Convert given timestamp into a certain range."""

    timestamp = int(time.mktime(time.strptime(timestamp, "%Y-%m-%d %H:%M:%S")))
    timestamp_gte = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.localtime(timestamp - n))
    timestamp_lte = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.localtime(timestamp + n))

    return timestamp_gte, timestamp_lte


def print_sessions(sessions):
    """Print selected session data from the response in a format."""

    for session in sessions:
        print(
            f"Time: {session['start_timestamp_utc'][:-1].replace('T', ' ')}"
            + f", Src: {session['ip']}:{session['port']}, Dst: {session['connected_ip']}:{session['connected_port']}"
            + f", Proto: {session['protocol']}"
            + f", Data In: {session['octets_in']}, Data Out: {session['octets_out']}"
            + f", Packets In: {session['packets_in']}, Packets Out: {session['packets_out']}"
        )


def print_alerts(alerts):
    """Print queried alerts data."""

    for alert in alerts:
        print(json.dumps(alert, indent=4, sort_keys=True))


def create_params(event, translation, time_range):
    """Create query parameters from input of another labeling scheme (key names)."""

    params = {}

    for param_key in translation:
        try:
            if translation[param_key] == "timestamp_gte":
               params[param_key] = timestamp_range(event["timestamp"], time_range)[0]
            elif translation[param_key] == "timestamp_lte":
               params[param_key] = timestamp_range(event["timestamp"], time_range)[1]
            else:
               params[param_key] = event[translation[param_key]]
        except KeyError:
            pass

    return params


def main():
    """Read a file containing information about an event, query SWC API services and display session/alert information
       relevant to the event or otherwise potentially useful for investigating the event."""

    try:
        with open(SWC_EVENT_FILE_NAME, "r") as _:
            event = json.load(_)

    except (IOError):
        print(f"\nError: Unable to read from '{SWC_EVENT_FILE_NAME}'...\n", file=sys.stderr)
        sys.exit(2)

    print("\nEvent matching session(s):")
    translation = {
        "ip": "src_ip",
        "port": "src_port",
        "connected_ip": "dst_ip",
        "connected_port": "dst_port",
        "protocol": "proto",
        "start_timestamp_utc__gte": "timestamp_gte",
        "start_timestamp_utc__lte": "timestamp_lte",
    }
    params = create_params(event, translation, 5)
    print_sessions(query_service(SWC_SESSION_URL, params))

    print("\nOther session(s) matching the source and destination IP addresses (event time +/- 30secs):")
    translation = {
        "ip": "src_ip",
        "connected_ip": "dst_ip",
        "start_timestamp_utc__gte": "timestamp_gte",
        "start_timestamp_utc__lte": "timestamp_lte",
    }
    params = create_params(event, translation, 30)
    sessions = query_service(SWC_SESSION_URL, params)
    sessions.sort(key=lambda x: int(x["octets_in"]) + int(x["octets_out"]), reverse=True)
    print_sessions(sessions)

    print("\nTop talkers matching the source IP address (event time +/- 30secs; displaying top 5):")
    translation = {
        "ip": "src_ip",
        "start_timestamp_utc__gte": "timestamp_gte",
        "start_timestamp_utc__lte": "timestamp_lte",
    }
    params = create_params(event, translation, 30)
    sessions = query_service(SWC_SESSION_URL, params)
    sessions.sort(key=lambda x: int(x["octets_in"]) + int(x["octets_out"]), reverse=True)
    sessions = sessions[:5]
    print_sessions(sessions)

    print("\nAlert(s) (event time +/- 30 mins):")
    translation = {
        "time__gte": "timestamp_gte",
        "time__lte": "timestamp_lte",
    }
    params = create_params(event, translation, 3600 * 24 * 7)
    params["status"] = "all"
    alerts = query_service(SWC_ALERT_URL, params)
    print_alerts(alerts)

if __name__ == "__main__":
    sys.exit(main())
