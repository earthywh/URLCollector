import subprocess
import os
import sys
import shutil
from datetime import datetime
from urllib.parse import urlparse, unquote
import re
import requests
import hashlib

def find_executable(name):
    """Find the full path of an executable."""
    return shutil.which(name) or f"/root/go/bin/{name}"

def read_domains(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def run_command(command, input_file=None, output_file=None):
    try:
        if input_file:
            if "subfinder" in command[0]:
                command.extend(["-dL", input_file])
            elif "katana" not in command[0]:  # katana uses -list instead of -l
                command.extend(["-l", input_file])
        if output_file:
            command.extend(["-o", output_file])
        
        print(f"Running command: {' '.join(command)}")
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running command {' '.join(command)}: {e}")
        print(f"Error output: {e.stderr}")
        return None

def extract_subdomains(url):
    parsed_url = urlparse(url)
    domain_parts = parsed_url.netloc.split('.')
    if len(domain_parts) > 2:
        return '.'.join(domain_parts)
    return None

def deduplicate_file(file_path):
    with open(file_path, 'r') as f:
        lines = set(f.readlines())
    with open(file_path, 'w') as f:
        f.writelines(sorted(lines))

def combine_files(file1, file2, output_file):
    with open(file1, 'r') as f1, open(file2, 'r') as f2, open(output_file, 'w') as out:
        lines = set(f1.readlines() + f2.readlines())
        out.writelines(sorted(lines))

def is_js_url(url):
    # Use a regular expression to match .js files, including those with query parameters
    return bool(re.search(r'\.js($|\?)', url.lower()))

def filter_js_urls(input_file, output_file):
    print(f"Filtering JavaScript URLs from {input_file}")
    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
        for line in infile:
            if is_js_url(line.strip()):
                outfile.write(line)
    print(f"JavaScript URLs saved to {output_file}")

def download_js_files(input_file, output_folder):
    print(f"Downloading JavaScript files from URLs in {input_file}")
    os.makedirs(output_folder, exist_ok=True)
    
    with open(input_file, 'r') as infile:
        for line in infile:
            url = line.strip()
            parsed_url = urlparse(url)
            
            # Create a filename from the URL path
            path_parts = parsed_url.path.split('/')
            js_filename = path_parts[-1] if path_parts[-1] else 'index.js'
            
            # Add a unique identifier for URLs with query parameters
            if parsed_url.query:
                query_hash = hashlib.md5(parsed_url.query.encode()).hexdigest()[:10]
                js_filename = f"{js_filename}_{query_hash}"
            
            # Ensure the filename ends with .js
            if not js_filename.lower().endswith('.js'):
                js_filename += '.js'
            
            output_path = os.path.join(output_folder, js_filename)
            
            try:
                print(f"Downloading: {url}")
                response = requests.get(url, verify=False, timeout=30)
                response.raise_for_status()
                
                with open(output_path, 'wb') as f:
                    f.write(response.content)
                
                print(f"Downloaded: {url} -> {output_path}")
            except requests.exceptions.RequestException as e:
                print(f"Failed to download {url}: {e}")
            except Exception as e:
                print(f"Unexpected error while downloading {url}: {e}")

    print(f"JavaScript files downloaded to {output_folder}")

def create_output_folder():
    # Create a folder name with current date and time
    folder_name = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_folder = os.path.join(os.getcwd(), folder_name)
    os.makedirs(output_folder, exist_ok=True)
    print(f"Created output folder: {output_folder}")
    return output_folder

def extract_secrets_with_jsluice(js_folder, output_file):
    print(f"Extracting secrets from JavaScript files in {js_folder}")
    
    # List of possible jsluice locations
    jsluice_paths = [
        "/root/go/bin/jsluice",
        "/usr/local/bin/jsluice",
        "/usr/bin/jsluice",
        "jsluice"  # This will search in PATH
    ]
    
    jsluice_path = None
    for path in jsluice_paths:
        if os.path.exists(path) or (path == "jsluice" and shutil.which(path)):
            jsluice_path = path
            break
    
    if not jsluice_path:
        print("Error: jsluice binary not found. Please install jsluice or provide its path.")
        return

    print(f"Using jsluice at: {jsluice_path}")

    with open(output_file, 'w') as outfile:
        for filename in os.listdir(js_folder):
            if filename.endswith('.js'):
                file_path = os.path.join(js_folder, filename)
                if os.path.getsize(file_path) > 0:
                    print(f"Processing: {filename}")
                    command = f"{jsluice_path} secrets '{file_path}'"
                    print(f"Executing command: {command}")
                    
                    try:
                        # Use os.system for a more direct execution
                        exit_code = os.system(f"{command} >> {output_file} 2>&1")
                        
                        print(f"Command exit code: {exit_code}")
                        
                        if exit_code == 0:
                            print(f"Processed {filename} successfully")
                        else:
                            print(f"Error processing {filename}. Exit code: {exit_code}")

                    except Exception as e:
                        print(f"Exception while processing {filename}: {e}")
                        print(f"Python version: {sys.version}")
                        print(f"Operating system: {os.name}")

    print(f"Secrets extraction completed. Results saved to {output_file}")
    print(f"Contents of {output_file}:")
    with open(output_file, 'r') as f:
        print(f.read())

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 urlscollect.py <input_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)

    output_folder = create_output_folder()
    
    gau_output_file = os.path.join(output_folder, "gau.txt")
    subdomains_file = os.path.join(output_folder, "subdomains.txt")
    subfinder_output = os.path.join(output_folder, "subfinder_subdomains.txt")
    act_urls_file = os.path.join(output_folder, "act_urls.txt")
    katana_output = os.path.join(output_folder, "katana_urls.txt")
    final_urls_file = os.path.join(output_folder, "urls.txt")
    js_urls_file = os.path.join(output_folder, "js_urls.txt")
    js_files_folder = os.path.join(output_folder, "jsfiles")
    secrets_output_file = os.path.join(output_folder, "secrets.txt")

    # Create jsfiles folder
    os.makedirs(js_files_folder, exist_ok=True)

    print("Step 1: Reading domains from input file")
    domains = read_domains(input_file)
    
    print("Step 2: Running gau for each domain")
    with open(gau_output_file, 'w') as gau_file:
        for domain in domains:
            print(f"  Processing domain: {domain}")
            gau_output = run_command([find_executable("gau"), "--blacklist", "png,jpg,gif", domain])
            if gau_output:
                gau_file.write(gau_output)

    print("Step 3: Extracting subdomains from gau.txt")
    subdomains = set()
    with open(gau_output_file, 'r') as gau_file:
        for line in gau_file:
            subdomain = extract_subdomains(line.strip())
            if subdomain:
                subdomains.add(subdomain)

    with open(subdomains_file, 'w') as sub_file:
        for subdomain in sorted(subdomains):
            sub_file.write(f"{subdomain}\n")

    print("Step 4: Running subfinder")
    run_command(["/root/go/bin/subfinder"], input_file, subfinder_output)

    print("Step 5: Combining and deduplicating subdomains")
    combine_files(subdomains_file, subfinder_output, subdomains_file)
    deduplicate_file(subdomains_file)

    print("Step 6: Running httpx")
    run_command(["/root/go/bin/httpx"], subdomains_file, act_urls_file)

    print("Step 7: Running katana")
    run_command(["/root/go/bin/katana", "-list", act_urls_file, "-silent", "-d", "6", "-rl", "25", "-jc", "-f", "qurl", "-o", katana_output])

    print("Step 8: Combining and deduplicating final URLs")
    combine_files(katana_output, gau_output_file, final_urls_file)
    deduplicate_file(final_urls_file)

    print("Step 9: Filtering JavaScript URLs")
    filter_js_urls(final_urls_file, js_urls_file)

    print("Step 10: Downloading JavaScript files")
    download_js_files(js_urls_file, js_files_folder)

    print("Step 11: Extracting secrets from JavaScript files")
    extract_secrets_with_jsluice(js_files_folder, secrets_output_file)

    print(f"Process completed. All output files are stored in: {output_folder}")
    print(f"JavaScript files are downloaded to {js_files_folder}")
    print(f"Extracted secrets are stored in {secrets_output_file}")

if __name__ == "__main__":
    main()
