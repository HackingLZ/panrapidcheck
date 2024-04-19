## Device -> Support -> Generate Tech Support file
import os
import re
import tarfile
import gzip
import shutil
import argparse
import zipfile
from tabulate import tabulate

LOG_FOLDER = 'var/log/pan'
NGINX_LOG_FOLDER = 'var/log/nginx'
GP_SVC_LOG_PATTERN = 'gpsvc.log*'
SSL_VPN_ACCESS_LOG_PATTERN = 'sslvpn-access.log*'
SSL_VPN_ERROR_LOG_PATTERN = 'sslvpn_ngx_error.log*'
TELEMETRY_SEND_LOG_PATTERN = 'device_telemetry_send*'
NGINX_ACCESS_LOG_PATTERN = 'sslvpn_access.log*'

def extract_tgz(input_file: str) -> str:
    output_folder = input_file[:-4] + "-extracted"
    if os.path.exists(output_folder):
        print(f"Utilizing already extracted folder: {output_folder}")
    else:
        if input_file.endswith(".tgz"):
            if not os.path.exists(output_folder):
                os.makedirs(output_folder)
            with tarfile.open(input_file, "r:gz") as tar:
                for member in tar:
                    tar.extract(member, path=output_folder)
            print(f"Extracted {input_file} to {output_folder}")
        else:
            print("Error: The file does not have a '.tgz' extension")
    return output_folder

def recursively_unzip(directory: str) -> None:
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.gz'):
                gz_path = os.path.join(root, file)
                uncompressed_path = os.path.join(root, file[:-3])
                with gzip.open(gz_path, 'rb') as f_in, open(uncompressed_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
                print(f"Decompressed {gz_path}")
            elif file.endswith('.zip'):
                zip_path = os.path.join(root, file)
                zip_folder = os.path.splitext(zip_path)[0]
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(zip_folder)
                print(f"Extracted {zip_path} to {zip_folder}")

def extract_file_names(output: str) -> list:
    lines = output.strip().split("\n")
    file_names = []

    for line in lines:
        match = re.search(r'/([^/]+\.[^/]+)(?=\))', line)
        if match:
            file_name = match.group(1)
            if re.match(r'^[a-zA-Z0-9._-]+$', file_name):
                file_names.append(file_name)

    return file_names

def unmarshal_hunt(extracted_folder: str) -> str:
    regex_pattern = re.compile(r"failed to unmarshal session(?!.*\([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\) map , EOF)")
    file_pattern = GP_SVC_LOG_PATTERN

    output = []
    for root, dirs, files in os.walk(extracted_folder):
        if root.startswith(os.path.join(extracted_folder, LOG_FOLDER)):
            matching_files = [file for file in files if re.match(file_pattern, file)]
            for file in matching_files:
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                    for line in file:
                        match = regex_pattern.search(line)
                        if match:
                            output.append([file_path, line.strip()])

    print_table(output, "Unmarshal Session Errors")
    return "\n".join([f"{entry[0]} {entry[1]}" for entry in output])

def access_log_hunt(extracted_folder: str, file_names: list) -> None:
    output = []
    nginx_log_folder = os.path.join(extracted_folder, NGINX_LOG_FOLDER)
    if os.path.exists(nginx_log_folder):
        for root, dirs, files in os.walk(nginx_log_folder):
            for file in files:
                if re.match(NGINX_ACCESS_LOG_PATTERN, file):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            for file_name in file_names:
                                pattern = re.compile(f".*{re.escape(file_name)}.*")
                                if pattern.search(line):
                                    output.append([file_path, line.strip()])
                                    break

    print_table(output, "Access Log Hunt")

def c2_ioc_hunt(extracted_folder: str) -> None:
    with open('iocs.txt', 'r') as file:
        iocs = [line.strip() for line in file if line.strip()]
    ioc_pattern = re.compile('|'.join(re.escape(ioc) for ioc in iocs))

    file_patterns = [
        SSL_VPN_ACCESS_LOG_PATTERN,
        SSL_VPN_ERROR_LOG_PATTERN,
        NGINX_ACCESS_LOG_PATTERN
    ]

    output = []
    for root, dirs, files in os.walk(extracted_folder):
        if root.startswith(os.path.join(extracted_folder, LOG_FOLDER)) or root.startswith(os.path.join(extracted_folder, NGINX_LOG_FOLDER)):
            for file_pattern in file_patterns:
                matching_files = [file for file in files if re.match(file_pattern, file)]
                for file in matching_files:
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                        for line in file:
                            if ioc_pattern.search(line):
                                output.append([file_path, line.strip()])

    print_table(output, "C2 IoC Matches")

def telemetry_send_hunt(extracted_folder: str) -> None:
    file_pattern = TELEMETRY_SEND_LOG_PATTERN

    output = []
    for root, dirs, files in os.walk(extracted_folder):
        if root.startswith(os.path.join(extracted_folder, LOG_FOLDER)):
            matching_files = [file for file in files if re.match(file_pattern, file)]
            for file in matching_files:
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                    for line in file:
                        if "send_file_cmd" in line:
                            output.append([file_path, line.strip()])

    print_table(output, "Telemetry Send Commands")

def print_table(data: list, title: str) -> None:
    if data:
        headers = ["File Path", "Match"]
        print(f"\n{title}:\n")
        print(tabulate(data, headers=headers))
    else:
        print(f"\n{title}:\nNo matches found.")

def main() -> None:
    parser = argparse.ArgumentParser(description="PaloAlto Support File Parser")
    parser.add_argument("input_file", type=str, help="The path to support .tgz")
    args = parser.parse_args()

    extracted_folder = extract_tgz(args.input_file)
    recursively_unzip(extracted_folder)
    unmarshal_output = unmarshal_hunt(extracted_folder)
    file_names = extract_file_names(unmarshal_output)
    print(extract_file_names(unmarshal_output))
    access_log_hunt(extracted_folder, file_names)
    c2_ioc_hunt(extracted_folder)
    telemetry_send_hunt(extracted_folder)

if __name__ == "__main__":
    main()
