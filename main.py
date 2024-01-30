import os
import asyncio
import json
from time_utils.time_convertor import string_to_datetime
from convertion_script.update_json import update
from nvd_api_2.nvd_api import get_cves



def main():
   """
   Get lastModStartDate from 2024-entryIndex.json and fetch data
   from lastModStartDate to current time then update existing Json feed.
   """
   currPath = os.path.realpath(__file__)
   parent = os.path.dirname(currPath)
   reqpath = os.path.join(parent, 'json_feed/2024-entryIndex.json')
   lastUpdated = ""
   with open(reqpath, "r") as file:
      f = json.load(file)
      lastUpdated = f["lastUpdated"]

   lastModStartDate = string_to_datetime(lastUpdated)
   responses = asyncio.run(get_cves(lastModStartDate))
   update(responses)

if __name__ == "__main__":
   main()