import asyncio
import os
import aiohttp
import math
from tqdm import tqdm
from datetime import datetime
from time_utils.time_convertor import convert_date_to_nvd_date_api2


URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HTTP_HEADERS = {
    "User-Agent": f"cve-bin-tool/3.3 (https://github.com/intel/cve-bin-tool/)",
    "apiKey": os.environ.get("NVD_API_KEY")
}

PAGE_SIZE = 2000
DELAY = 2


params = {
    "lastModEndDate": convert_date_to_nvd_date_api2(datetime.now())
}

async def fetch_total_entries(session, url, params):
    async with session.get(url, params=params, headers=HTTP_HEADERS) as response:
        try:
            response.raise_for_status()
            data = await response.json()
            return int(data.get('totalResults', 0))
        except aiohttp.ClientResponseError as e:
            if e.status == 403:
                print(f"Forbidden: Check API key and permissions.")
            else:
                print(f"Error: {e.status}, {await response.text()}")
            return 0
        except aiohttp.ClientError as e:
            print(f"Client Error: {e}")
            return 0

async def fetch(session, url, params):
    async with session.get(url, params=params, headers=HTTP_HEADERS) as response:
        try:
            response.raise_for_status()
            return await response.json()
        except aiohttp.ClientResponseError as e:
            if e.status == 403:
                print(f"Forbidden: Check API key and permissions.")
            else:
                print(f"Error: {e.status}, {await response.text()}")
            return None
        except aiohttp.ClientError as e:
            print(f"Client Error: {e}")
            return None

def get_tasks(session, total_entries):
    indexes = math.ceil(total_entries / PAGE_SIZE)
    return [fetch(session, URL, {"startIndex": i * PAGE_SIZE, **params}) for i in range(indexes)]

async def get_cves(starttime):
    params["lastModStartDate"] = convert_date_to_nvd_date_api2(starttime)
    async with aiohttp.ClientSession() as session:
        total_entries = await fetch_total_entries(session, URL, params)
        print("Total number of entries found are:", total_entries)
        
        tasks = get_tasks(session, total_entries)
        result = []
        with tqdm(total=len(tasks), desc="Progress") as pbar:
            for task in tasks:
                data = await task
                if data:
                    result.append(data)
                pbar.update(1)
                await asyncio.sleep(DELAY)
        return result

if __name__ == "__main__":
    result = asyncio.run(get_cves())





