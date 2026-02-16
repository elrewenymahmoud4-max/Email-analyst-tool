import sys
import os
import email
import re
import socket
import requests
import base64
import hashlib
from email import policy
from email.parser import BytesParser

# ============================
# User input for VirusTotal API
# ============================
VT_API_KEY = input("Enter your VirusTotal API Key: ").strip()

def extract_sender_ip(msg):
    received_headers = msg.get_all("received", [])
    for header in received_headers:
        match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', header)
        if match:
            return match.group(1)
    return "Not found"

def resolve_host(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Could not resolve"

def extract_urls(text):
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    return re.findall(url_pattern, text)

def check_url_virustotal(url):
    try:
        headers = {"x-apikey": VT_API_KEY}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        response = requests.get(report_url, headers=headers)
        if response.status_code != 200:
            return f"VT API error: status={response.status_code} response={response.text[:120]}"

        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        results = data["data"]["attributes"]["last_analysis_results"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious + suspicious == 0:
            return "legitimate"

        engines = [engine for engine, res in results.items() if res["category"] in ["malicious","suspicious"]]
        return f"the red flages is {len(engines)} : {', '.join(engines)}"
    except Exception as e:
        return f"VT error: {e}"

def check_file_virustotal(file_bytes):
    try:
        sha1 = hashlib.sha1(file_bytes).hexdigest()
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        md5 = hashlib.md5(file_bytes).hexdigest()

        headers = {"x-apikey": VT_API_KEY}
        report_url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        response = requests.get(report_url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            results = data["data"]["attributes"]["last_analysis_results"]

            malicious = stats.get("malicious",0)
            suspicious = stats.get("suspicious",0)

            if malicious + suspicious == 0:
                description = "legitimate"
            else:
                engines = [engine for engine, res in results.items() if res["category"] in ["malicious","suspicious"]]
                description = f"the red flages is {len(engines)} : {', '.join(engines)}"
        else:
            description = "not found in VirusTotal"

        return sha1, sha256, md5, description

    except Exception as e:
        return "error", "error", "error", f"VT error: {e}"

def extract_spf_dkim(msg):
    spf_result = "Not found"
    dkim_result = "Not found"

    auth_headers = msg.get_all("Authentication-Results", [])
    for header in auth_headers:
        spf_match = re.search(r"spf=(pass|fail|neutral|softfail|permerror|temperror)", header, re.IGNORECASE)
        if spf_match:
            spf_result = spf_match.group(1).lower()

        dkim_match = re.search(r"dkim=(pass|fail|neutral|policy|temperror|permerror)", header, re.IGNORECASE)
        if dkim_match:
            dkim_result = dkim_match.group(1).lower()

    spf_header = msg.get("Received-SPF")
    if spf_header:
        spf_result = spf_header.split()[0]

    return spf_result, dkim_result

# ========================
# Unique output file name
# ========================
def get_unique_filename(directory, base_name="output", ext=".txt"):
    i = 0
    while True:
        if i == 0:
            filename = f"{base_name}{ext}"
        else:
            filename = f"{base_name} {i}{ext}"
        full_path = os.path.join(directory, filename)
        if not os.path.exists(full_path):
            return full_path
        i += 1

# ========================
# Main function
# ========================
def analyze_auto_search(filename):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, filename)

    if not os.path.exists(file_path):
        print(f"Error: The file '{filename}' was not found in this folder.")
        return

    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        # Headers
        date        = msg.get('date', 'Not found')
        subject     = msg.get('subject', 'No Subject')
        to          = msg.get('to', 'Not found')
        sender      = msg.get('from', 'Unknown Sender')
        reply_to    = msg.get('reply-to', 'Not found')
        return_path = msg.get('return-path', 'Not found')
        message_id  = msg.get('message-id', 'Not found')
        sender_ip = extract_sender_ip(msg)
        resolved  = resolve_host(sender_ip) if sender_ip != "Not found" else "N/A"
        spf_result, dkim_result = extract_spf_dkim(msg)

        # Body
        body = ""
        body_part = msg.get_body(preferencelist=('plain'))
        if body_part:
            body = body_part.get_content()

        # URLs
        urls = extract_urls(body)
        url_results = []
        for u in urls:
            result = check_url_virustotal(u)
            url_results.append((u, result))

        # Attachments
        attachments = [part for part in msg.iter_attachments()]
        attach_results = []
        for att in attachments:
            filename = att.get_filename() or "unknown"
            file_bytes = att.get_content()
            sha1, sha256, md5, description = check_file_virustotal(file_bytes)
            attach_results.append({
                "filename": filename,
                "sha1": sha1,
                "sha256": sha256,
                "md5": md5,
                "description": description
            })

        # Output file
        output_file = get_unique_filename(script_dir, "output", ".txt")
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(f"Date: {date}\n")
            f.write(f"Subject: {subject}\n")
            f.write(f"To: {to}\n")
            f.write(f"From: {sender}\n")
            f.write(f"Reply-To: {reply_to}\n")
            f.write(f"Return-Path: {return_path}\n")
            f.write(f"Sender IP: {sender_ip}\n")
            f.write(f"Resolve Host: {resolved}\n")
            f.write(f"Message-ID: {message_id}\n")
            f.write(f"SPF: {spf_result}\n")
            f.write(f"DKIM: {dkim_result}\n\n")

            f.write("URLs\n")
            f.write("======================================\n\n")
            for url, result in url_results:
                f.write(f"{url}\n")
                f.write(f"{result}\n\n")

            f.write("Attachments\n")
            f.write("======================================\n\n")
            for att in attach_results:
                f.write(f"Attachment Name: {att['filename']}\n")
                f.write(f"MD5: {att['md5']}\n")
                f.write(f"SHA1: {att['sha1']}\n")
                f.write(f"SHA256: {att['sha256']}\n")
                f.write(f"Description: {att['description']}\n\n")

            # Author info
            author_info = ": this code made by Mahmoud elreweny\nmy YT channel : https://www.youtube.com/@Elreweny-mt2lw\n"
            f.write(author_info)

        # Print author info
        print("\n" + author_info)
        print(f"Analysis finished. Results saved in: {output_file}")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <filename.eml>")
    else:
        analyze_auto_search(sys.argv[1])
