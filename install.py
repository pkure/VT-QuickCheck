"""Install (or update) the 'VirusTotal Check' right-click Service:  /usr/bin/python3 install.py
Builds ~/Library/Services/VirusTotal Check.workflow from the shape macOS Quick Actions use (Run Shell Script that
gets the selected text on stdin) and points it at vtcheck.py in this folder. Uninstall: delete that .workflow."""

import plistlib
import shutil
import subprocess
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEST = Path.home() / "Library" / "Services" / "VirusTotal Check.workflow"
CMD = f'/usr/bin/python3 -I "{HERE / "vtcheck.py"}"'


def action() -> dict:
    return {"action": {
        "AMAccepts": {"Container": "List", "Optional": True, "Types": ["com.apple.cocoa.string"]},
        "AMActionVersion": "2.0.3", "AMApplication": ["Automator"],
        "AMParameterProperties": {k: {} for k in ("COMMAND_STRING", "CheckedForUserDefaultShell", "inputMethod", "shell", "source")},
        "AMProvides": {"Container": "List", "Types": ["com.apple.cocoa.string"]},
        "ActionBundlePath": "/System/Library/Automator/Run Shell Script.action", "ActionName": "Run Shell Script",
        "ActionParameters": {"COMMAND_STRING": CMD, "CheckedForUserDefaultShell": True, "inputMethod": 0,
                             "shell": "/bin/zsh", "source": ""},
        "BundleIdentifier": "com.apple.RunShellScript", "CFBundleVersion": "2.0.3",
        "CanShowSelectedItemsWhenRun": False, "CanShowWhenRun": True, "Category": ["AMCategoryUtilities"],
        "Class Name": "RunShellScriptAction", "InputUUID": str(uuid.uuid4()).upper(),
        "Keywords": ["Shell", "Script", "Command", "Run", "Unix"], "OutputUUID": str(uuid.uuid4()).upper(),
        "UUID": str(uuid.uuid4()).upper(), "UnlocalizedApplications": ["Automator"],
        "arguments": {str(i): {"default value": dv, "name": n, "required": "0", "type": "0", "uuid": str(i)}
                      for i, (n, dv) in enumerate([("inputMethod", 0), ("CheckedForUserDefaultShell", False),
                                                   ("source", ""), ("COMMAND_STRING", ""), ("shell", "")])},
        "isViewVisible": 1, "location": "309.0:316.0", "nibPath": "/System/Library/Automator/Run Shell Script.action/Contents/Resources/Base.lproj/main.nib"},
        "isViewVisible": 1}


def main() -> None:
    if DEST.exists():
        shutil.rmtree(DEST)
    (DEST / "Contents").mkdir(parents=True)
    info = {"NSServices": [{"NSBackgroundColorName": "background", "NSIconName": "NSActionTemplate",
                            "NSMenuItem": {"default": "VirusTotal Check"}, "NSMessage": "runWorkflowAsService",
                            "NSSendTypes": ["public.utf8-plain-text"]}]}
    doc = {"AMApplicationBuild": "534", "AMApplicationVersion": "2.10", "AMDocumentVersion": "2",
           "actions": [action()], "connectors": {},
           "workflowMetaData": {"applicationBundleIDsByPath": {}, "applicationPaths": [], "inputTypeIdentifier":
                                "com.apple.Automator.text", "outputTypeIdentifier": "com.apple.Automator.nothing",
                                "presentationMode": 11, "processesInput": False,
                                "serviceInputTypeIdentifier": "com.apple.Automator.text",
                                "serviceOutputTypeIdentifier": "com.apple.Automator.nothing",
                                "serviceProcessesInput": False, "systemImageName": "NSActionTemplate",
                                "useAutomaticInputType": False, "workflowTypeIdentifier": "com.apple.Automator.servicesMenu"}}
    with open(DEST / "Contents" / "Info.plist", "wb") as fh:
        plistlib.dump(info, fh)
    with open(DEST / "Contents" / "document.wflow", "wb") as fh:
        plistlib.dump(doc, fh)
    subprocess.run(["/System/Library/CoreServices/pbs", "-flush"], check=False)
    print(f"installed: {DEST}\nruns: {CMD}")


if __name__ == "__main__":
    main()
