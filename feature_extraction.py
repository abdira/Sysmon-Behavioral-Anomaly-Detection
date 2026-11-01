import re


def extract_features(event):

    message = event.get("message", {})

    event_id = int(event.get("event_id", 0))

    image = message.get("Image", "")
    parent_image = message.get("ParentImage", "")
    command_line = message.get("CommandLine", "")
    user = message.get("User", "")

    image_lower = image.lower()

    command_length = len(command_line)

    arguments = command_line.split()
    argument_count = len(arguments)

    has_powershell = int(
        "powershell.exe" in image_lower
    )

    has_encoded_command = int(
        bool(
            re.search(
                r"(?i)(?:^|\s)-encodedcommand(?:\s|$)",
                command_line
            )
        )
    )

    script_interpreters = [
        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe"
    ]

    has_script_interpreter = int(
        any(
            interpreter in image_lower
            for interpreter in script_interpreters
        )
    )

    suspicious_lolbins = [
        "rundll32.exe",
        "regsvr32.exe",
        "mshta.exe",
        "certutil.exe",
        "bitsadmin.exe"
    ]

    has_suspicious_lolbin = int(
        any(
            lolbin in image_lower
            for lolbin in suspicious_lolbins
        )
    )

    return {
        "EventID": event_id,
        "utc_time": event.get("utc_time"),
        "EventRecordID": event.get("EventRecordID"),
        "CommandLine": command_line,
        "ParentCommandLine": message.get("ParentCommandLine", ""),
        "command_length": command_length,
        "argument_count": argument_count,
        "has_powershell": has_powershell,
        "has_encoded_command": has_encoded_command,
        "has_script_interpreter": has_script_interpreter,
        "has_suspicious_lolbin": has_suspicious_lolbin,
        "Image": image,
        "ParentImage": parent_image,
        "User": user
    }