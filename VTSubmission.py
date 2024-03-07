#Evan Constantino
#VirusTotal hash submissions using API
import hashlib, os, requests, config, urllib3, pprint
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
    binary = open_file()
    hash = sha256hashing(binary)
    print(f'SHA256: {hash}')
    hash = hash.upper()
    description_info, known_distributor, product_info, verified, detections = vtrequest(hash)

    if len(known_distributor) != 0:
        for i in known_distributor:
            print(f'Distributor: {i}')
    else:
        print(f'Distributor: N\A')
    if len(verified) != 0:
        print(f'File is {verified}')
    else:
        print(f'File is unsigned')
    if description_info != "":
        print(f'Description: {description_info}')
    else:
        print(f'Description: N\A')
    if product_info != "":
        print(f'Product Info: {product_info}')
    else:
        print(f'Description: N\A')
    print(f'{detections} vendors flagged the file belonging to this hash as malicious')

def open_file():
    while True:
        filepath = input("Enter in the full file path of the file you'd like to find the hash of: ")
        if os.path.exists(filepath):
            return open(filepath,"rb")
        else:
            print(f'There is no file found under {filepath}, please ensure you are entering the full path!')

def sha256hashing(binary):
    sha256hasher = hashlib.sha256()
    while sha256chunk := binary.read(4096):
        sha256hasher.update(sha256chunk)
    return sha256hasher.hexdigest()

def vtrequest(hash):
    url = f'https://www.virustotal.com/api/v3/files/{hash}'
    headers = {'x-apikey': config.api_key}
    response = requests.get(url, proxies=config.proxies, headers=headers, verify=config.verifyssl)
    if response.status_code == 200:
        data = response.json()
        known_distributor = data.get('data', {}).get('attributes', {}).get('known_distributors', {}).get('distributors', {})
        product_info = data.get('data', {}).get('attributes', {}).get('signature_info', {}).get('product', {})
        description_info = data.get('data', {}).get('attributes', {}).get('signature_info', {}).get('description', {})
        verified = data.get('data', {}).get('attributes', {}).get('signature_info', {}).get('verified', {})
        detections = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', {})
        return description_info, known_distributor, product_info, verified, detections
    else:
        print("Error: ", response.status_code, response.reason)
        print("If 404 error, it likely means the file hash submitted is not tied to any file current in the VirusTotal database")
        exit()

main()
