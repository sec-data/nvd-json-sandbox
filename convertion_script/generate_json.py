import json
import os
from time_utils.time_convertor import time_converter

def cpe_match_builder(cpeMatch)  -> list:
    children = []
    for it in cpeMatch:
        sans = {}
        if "vulnerable" in it:
            sans["vulnerable"] = it["vulnerable"]
        if "criteria" in it:
            sans["cpe23Uri"] = it["criteria"]
        if "versionStartExcluding" in it:
            sans["versionStartExcluding"] = it["versionStartExcluding"]
        if "versionStartIncluding" in it:
            sans["versionStartIncluding"] = it["versionStartIncluding"]
        if "versionEndExcluding" in it:
            sans["versionEndExcluding"] = it["versionEndExcluding"]
        if "versionEndIncluding" in it:
            sans["versionEndIncluding"] = it["versionEndIncluding"]
        sans["cpe_name"] = []
        children.append(sans)

    return children

def configToNode(config):
    node = {}
    if "operator" in config:
         node["operator"] = config["operator"]
    children = []
    for nodes in config["nodes"]:
        temp = {}
        temp["operator"] = nodes["operator"]
        temp["children"] = []
        temp["cpe_match"] = cpe_match_builder(nodes["cpeMatch"])
        children.append(temp)
    node["children"] = children
    node["cpe_match"] = []
    return node
    

def node_builder(configurations) -> list:
    nodes = []
    for config in configurations:
        node = configToNode(config)
        nodes.append(node)

    return nodes


def configurations_builder(config) -> dict:
    #need a little check
    configurations = {}
    configurations["CVE_data_version"] = "4.0"
    configurations["nodes"] = node_builder(config)
    return configurations

def references_builder(ref_arr) -> list:
     reference_data = []
     for api_ref in ref_arr:
        ref = {}
        if "url" in api_ref:
            ref["url"] = api_ref["url"]
        if "url" in api_ref:
            ref["name"] = api_ref["url"]
        if "source" in api_ref:
            ref["refsource"] = api_ref["source"]
        if "tags" in api_ref:
            ref["tags"] = api_ref["tags"]
        reference_data.append(ref)
     return {"reference_data" : reference_data}   
 
def description_builder(api_data) -> list:
     description = {}
     description["description_data"] = api_data["descriptions"]
     return description

def baseMetricV3_builder(cvssmetric) -> dict:
    baseMetricV3 = {}
    baseMetricV3["cvssV3"] = cvssmetric["cvssData"]
    baseMetricV3["exploitabilityScore"] = cvssmetric["exploitabilityScore"]
    baseMetricV3["impactScore"] = cvssmetric["impactScore"]
    return baseMetricV3

def baseMetricV2_builder(cvssmetric) -> dict:
    baseMetricV2 = {}
    if "cvssData" in cvssmetric:
        baseMetricV2["cvssV2"] = cvssmetric["cvssData"]
    if "baseSeverity" in cvssmetric:
        baseMetricV2["severity"] = cvssmetric["baseSeverity"]
    if "exploitabilityScore" in cvssmetric:
        baseMetricV2["exploitabilityScore"] = cvssmetric["exploitabilityScore"]
    if "impactScore" in cvssmetric:
        baseMetricV2["impactScore"] = cvssmetric["impactScore"]
    if "acInsufInfo" in cvssmetric:
        baseMetricV2["acInsufInfo"] = cvssmetric["acInsufInfo"]
    if "obtainAllPrivilege" in cvssmetric:
        baseMetricV2["obtainAllPrivilege"] = cvssmetric["obtainAllPrivilege"]
    if "obtainUserPrivilege" in cvssmetric:
        baseMetricV2["obtainUserPrivilege"] = cvssmetric["obtainUserPrivilege"]
    if "obtainOtherPrivilege" in cvssmetric:
        baseMetricV2["obtainOtherPrivilege"] = cvssmetric["obtainOtherPrivilege"]
    if "userInteractionRequired" in cvssmetric:
        baseMetricV2["userInteractionRequired"] = cvssmetric["userInteractionRequired"]
    return baseMetricV2

def impact_builder(metrics) -> dict:
    impact_dict = {}
    if "cvssMetricV31" in metrics:
        for it in metrics["cvssMetricV31"]:
            if it["type"] == "Primary":
               impact_dict["baseMetricV3"] = baseMetricV3_builder(it) 
               break
    elif "cvssMetricV30" in metrics:
         for it in metrics["cvssMetricV30"]:
            if it["type"] == "Primary":
               impact_dict["baseMetricV3"] = baseMetricV3_builder(it) 
               break
    
    if "cvssMetricV2" in metrics:
        for it in metrics["cvssMetricV2"]:
            if it["type"] == "Primary":
               impact_dict["baseMetricV2"] = baseMetricV2_builder(it) 
               break

    return impact_dict

def cve_meta_data_builder(api_cve) -> list:
    meta_data = {}
    meta_data["ID"] = api_cve["id"]
    meta_data["ASSIGNER"] = api_cve["sourceIdentifier"]
    return meta_data

def problemtype_builder(weaknesses):
    problemtype_data = []
    for weak in weaknesses:
        temp = {}
        if weak["type"] == "Primary":
            temp["description"] = weak["description"]
            problemtype_data.append(temp)
    return {"problemtype_data": problemtype_data}



def cve_builder(api_cve) -> list:
    #CVE_JSON_4.0_min_1.1.schema
    cve = {}
    cve["data_type"] = "CVE"		
    cve["data_format"] = "MITRE"		
    cve["data_version"] = "4.0"			
    cve["CVE_data_meta"] = cve_meta_data_builder(api_cve)	
    if "weaknesses" in api_cve:	
        cve["problemtype"] = problemtype_builder(api_cve["weaknesses"])	
    #references and description are required in api2
    cve["references"] = references_builder(api_cve["references"])		
    cve["description"] = description_builder(api_cve)
    return cve	


def cve_item_builder(vul) -> dict: 
    dict = {}
    dict["cve"] = cve_builder(vul["cve"])
    if "configurations" in vul["cve"]:
        dict["configurations"] = configurations_builder(vul["cve"]["configurations"])
    dict["impact"] = impact_builder(vul["cve"]["metrics"])
    dict["publishedDate"] = time_converter(vul["cve"]["published"])
    dict["lastModifiedDate"] = time_converter(vul["cve"]["lastModified"])
    
    return dict


current_directory = os.getcwd()
filename = os.path.join(current_directory, "response2.json")

def json_builder(filename):
    json_feed = {}
    with open (filename, "r") as api2_file:
        api_data = json.load(api2_file)
        json_feed["CVE_data_type"] = "CVE"
        json_feed["CVE_data_format"] = "MITRE"
        json_feed["CVE_data_version"] = "4.0"
        json_feed["CVE_data_numberOfCVEs"] = str(api_data["totalResults"])
        json_feed["CVE_data_timestamp"] = time_converter(api_data["timestamp"])
        cve_list = []
        for vul in api_data["vulnerabilities"]:
            cve = cve_item_builder(vul)
            cve_list.append(cve)
            
        json_feed["CVE_Items"] = cve_list
    with open("temp.json", "w") as f:
        json.dump(json_feed, f, indent=4)		


if __name__ =="__main__":
    json_builder(filename)	