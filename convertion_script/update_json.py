import json
import os
from datetime import datetime
from convertion_script.generate_json import cve_item_builder
from time_utils.time_convertor import datetime_to_string


def update(responses):
    """
    Update the JSON files for the year 2024 with the given responses.
    """
    currPath = os.path.realpath(__file__)
    parent = os.path.dirname(currPath)
    parent = os.path.dirname(parent)
    json_feed_path = os.path.join(parent, 'json_feed')

    yearFile = {}
    entryIndex = {}
    
    with open(os.path.join(json_feed_path, "nvdcve-1.1-2024.json"), "r") as file:
        yearFile = json.load(file)

    with open(os.path.join(json_feed_path, "2024-entryIndex.json"), "r") as indexFile:
        entryIndex = json.load(indexFile)

    #go through all the responses received and update 2024 onces for now  
    year_entries = {}
    year_entries[2024] = []
    for response in responses: 
        for entry in response["vulnerabilities"]:
            id = entry["cve"]["id"]
            year = int(id.split('-')[1])
            if year == 2024:
                year_entries[year].append(entry)
    
    for entry in year_entries[2024]:
        ent = entry["cve"]["id"]
        converted_entry = cve_item_builder(entry)
        #if entry is present in entryIndex update it 
        #else create new
        if ent in entryIndex:
            index = entryIndex[ent]
            yearFile["CVE_Items"][index] = converted_entry

        else:
            yearFile["CVE_Items"].append(converted_entry)
            lastIndex = len(yearFile["CVE_Items"]) - 1
            entryIndex[ent] = lastIndex

    currTime = datetime_to_string(datetime.now())
    entryIndex["lastUpdated"] = currTime
    yearFile["CVE_data_timestamp"] = currTime
    yearFile["CVE_data_numberOfCVEs"] = str(len(yearFile["CVE_Items"]))
    
    with open(os.path.join(json_feed_path, "2024-entryIndex.json"), "w") as indexFile:
        json.dump(entryIndex, indexFile, indent=2)

    with open(os.path.join(json_feed_path, "nvdcve-1.1-2024.json"), "w") as file:
        json.dump(yearFile, file, indent=4)



