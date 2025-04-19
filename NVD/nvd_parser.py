import json
import zipfile
import requests

def download_file(url, file_name):
    try:
        response = requests.get(url)
        response.raise_for_status()

        with open(file_name, 'wb') as file:
            file.write(response.content)
        print(f"Файл '{file_name}' успешно скачан.")

    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP ошибка: {http_err}")
    except Exception as err:
        print(f"Ошибка: {err}")


def extract_cve_json(path_to_zip_file, directory_to_extract_to):
    with zipfile.ZipFile(path_to_zip_file, 'r') as zip_ref:
        zip_ref.extractall(directory_to_extract_to)


def parse_json(path_to_json):
    all_cves_array = []
    with open(path_to_json, 'r', encoding='utf-8') as cve_json:
        cve_dict = json.load(cve_json)

    cve_items = cve_dict.get('CVE_Items')

    for curr_cve in cve_items:
        cve_id = curr_cve.get('cve').get('CVE_data_meta').get('ID')
        description = curr_cve.get('cve').get('description').get('description_data')[0].get('value').strip()
        try:
            cvss = curr_cve.get('impact').get('baseMetricV3').get('cvssV3').get('baseScore')
        except:
            cvss = 0.0

        cve_tuple = (cve_id, description, cvss)
        all_cves_array.append(cve_tuple)

    return all_cves_array


def main_parser():
    print("Обновление базы данных уязвимостей NIST...")
    for i in range(2024, 2025 + 1):
        nist_url = f'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{i}.json.zip'
        zip_file_name=f'./nvdcve-1.1-{i}.json.zip'
        directory_to_extract_to = './extracted_cve_json'
        path_to_json=f'./{directory_to_extract_to}/nvdcve-1.1-{i}.json'

        download_file(nist_url, zip_file_name)
        extract_cve_json(zip_file_name, directory_to_extract_to)
        data_to_insert = parse_json(path_to_json)

    return data_to_insert