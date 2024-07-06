import time
import os
import json
import requests

def get_tenable_api_keys(file_path='configs.txt'):
    access_key = None
    secret_key = None
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith('Tenable_API_access_key='):
                access_key = line.strip().split('=')[1]
            elif line.startswith('Tenable_API_secret_key='):
                secret_key = line.strip().split('=')[1]
    if not access_key or not secret_key:
        raise ValueError('Tenable_API_access_key or Tenable_API_secret_key not found in the config file')
    return access_key, secret_key

def get_tenable_owner_id(file_path='configs.txt'):
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith('Tenable_owner_id='):
                return line.strip().split('=')[1]
    raise ValueError('Tenable_owner_id not found in the config file')

access_key, secret_key = get_tenable_api_keys()

# Run a web application scan and fetch results
def run_web_app_scan(target,timeout="00:10:00",sc_type='quick'):
    scan_id = web_app_scan(target,timeout,sc_type)
    while True:
        status=web_app_scan_status(scan_id)
        if(status=='completed'):
            web_app_scan_results(scan_id)
            print("Tenable web app scan is done, report is in the reports folder")
            break
        else:
            print("Scan still running")
            time.sleep(60)
            

# Run an net scan and fetch results
def run_netscan(name,targets,timeout_min=10):
    scan_id = netscan_create(name,targets,timeout_min)
    scan_uuid=netscan_launch(str(scan_id))
    while True:
        status=netscan_status(str(scan_id))
        if(status=='completed' or status=='canceled'):
            netscan_details(str(scan_id))
            print("Nessus scan is finished, the report is in the reports folder")
            break
        else:
            print("Scan is still running")
            time.sleep(60)

    






def web_app_scan(target,timeout,sc_type='quick'):
    
    if(sc_type=='quick'):
        temp="3e5862a6-e672-4a22-97b8-9301ec3439c8"
    elif(sc_type=='basic'):
        temp="987a4f69-d99b-4aa1-ad06-6d4db85c01f2"
    elif(sc_type=='standard'):
        temp="610598a9-e629-41d0-ad1b-7770e045d796"


    owner_id=get_tenable_owner_id()
    url = "https://cloud.tenable.com/was/v2/configs"

    payload = {
        "settings": { "timeout": timeout },
        "name": "Scan",
        "targets": [target],
        "description": "Scan",
        "template_id": temp,
        "owner_id": owner_id
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}"
    }

    response = requests.post(url, json=payload, headers=headers)
    resptext=json.loads(response.text)
    print(resptext.get('config_id'))

    url = "https://cloud.tenable.com/was/v2/configs/"+resptext.get('config_id')+"/scans"

    headers = {
    "accept": "application/json",
    "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}"
}
   
    response = requests.post(url, headers=headers)
    resptext=json.loads(response.text)
    return resptext.get('scan_id')


def web_app_scan_status(id):

    url = "https://cloud.tenable.com/was/v2/scans/"+id

    headers = {
        "accept": "application/json",
        "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}"
    }

    response = requests.get(url, headers=headers)
    resptext=json.loads(response.text)
    return resptext.get('status')

    print(response.text)

def web_app_scan_results(id):

    url = "https://cloud.tenable.com/was/v2/scans/"+id+"/vulnerabilities/search"

    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}"
    }

    response = requests.post(url, headers=headers)
    output_file_path = "reports/nessus.json"
    with open(output_file_path, 'w') as file:
        file.write(response.text)







def netscan_create(name,targets,timeout_min=10):

    url = "https://cloud.tenable.com/scans"

    payload = {
        "settings": {
            "enabled": False,
            "name": name,
            "scan_time_window": timeout_min,
            "text_targets": targets,
            "scanner_id": "01afb742-fac4-4f84-9148-0c7987b8c968"
        },
        "uuid": "731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65"
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}"
    }

    response = requests.post(url, json=payload, headers=headers)
    #print(response.text)
    resptext=json.loads(response.text)
    resptext=resptext.get('scan')
    return resptext.get('id')

def netscan_launch(id):
    url = "https://cloud.tenable.com/scans/"+id+"/launch"

    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}"
    }

    response = requests.post(url, headers=headers)
    resptext=json.loads(response.text)
    return resptext.get('scan_uuid')

def netscan_status(id):

    url = "https://cloud.tenable.com/scans/"+id+"/latest-status"

    headers = {
        "accept": "application/json",
        "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}"
    }

    response = requests.get(url, headers=headers)
    resptext=json.loads(response.text)
    return resptext.get('status')

def netscan_details(id):
    url = "https://cloud.tenable.com/scans/"+id

    headers = {
        "accept": "application/json",
        "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}"
    }

    response = requests.get(url, headers=headers)
    resptext=json.loads(response.text)
    resptext=resptext.get('vulnerabilities')
    resptext=','.join(map(str, resptext))

    output_file_path = "reports/nessus.json"
    with open(output_file_path, 'w') as file:
        file.write(resptext)

