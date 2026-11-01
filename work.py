import win32evtlog
import xml.etree.ElementTree as ET



channel = "Microsoft-Windows-Sysmon/Operational"

query = "*"

flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection

def get_sysmon_logs(max_records):
    handle = win32evtlog.EvtQuery(channel,flags,query)
    list_of_xml = []
    while True:
        logs = win32evtlog.EvtNext(handle,max_records)
        if not logs:
            break
        for log in logs:
            xml = win32evtlog.EvtRender(log,win32evtlog.EvtRenderEventXml)
            list_of_xml.append(xml)
    list_of_events = []
    for xmls in list_of_xml:
        root = ET.fromstring(xmls)
        EventID = root.findtext(".//{*}System/{*}EventID")
        EventRecordID = root.findtext(".//{*}System/{*}EventRecordID")
        Computer = root.findtext(".//{*}System/{*}Computer")
        TimeCreated = root.find(".//{*}System/{*}TimeCreated")
        utc_time = TimeCreated.attrib.get("SystemTime") if TimeCreated is not None else None
        message = {}
        for node in root.findall(".//{*}EventData/{*}Data"):
            name = node.attrib.get("Name")
            if name is not None:
                message[name] = node.text or ''

        event_dict = {
            'event_id': EventID,
            'EventRecordID': EventRecordID,
            'Computer': Computer,
            'utc_time': utc_time,
            'message': message
        }
        list_of_events.append(event_dict)
    return list_of_events

#def get_process_creation_info(ProcessGuid)

#sysmon = get_sysmon_logs(100)
#print(sysmon[0])