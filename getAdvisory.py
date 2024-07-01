import requests
import argparse
from datetime import datetime, timedelta
import urllib.parse
import re

def filter_and_format_nvras(nvras):
    filtered_nvras = []
    package_names = set()
    
    for nvra in nvras:
        # パッケージ名を抽出（最初の'-'の前まで）
        package_name = nvra.split('-')[0]
        package_names.add(package_name)
        
        # フィルタリング条件をチェック
        if (nvra.endswith(('.src.rpm', '.x86_64.rpm', '.noarch.rpm')) and 
            'debug' not in nvra.lower()):
            # 末尾の.src.rpm, .x86_64.rpm, .noarch.rpmを削除
            formatted_nvra = re.sub(r'\.(src|x86_64|noarch)\.rpm$', '', nvra)
            filtered_nvras.append(formatted_nvra)

    unique_nvras = list(set(filtered_nvras))
    return sorted(unique_nvras)  # ソートして返す

def extract_product_name(synopsis):
    match = re.match(r'(Important|Critical): (.*) security update', synopsis, re.IGNORECASE)
    if match:
        return match.group(2)
    return "Unknown product"

def get_advisory_names(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        return [advisory['name'] for advisory in data.get('advisories', [])]
    except requests.RequestException as e:
        print(f"リクエストエラー: {e}")
        return []
    except ValueError as e:
        print(f"JSONパースエラー: {e}")
        return []

def get_advisory_details(name):
    url = f"https://errata.rockylinux.org/api/v2/advisories/{name}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        advisory = data.get('advisory', {})
        synopsis = advisory.get('synopsis', '')
        nvras = [nvra for product in advisory.get('rpms', {}).values() for nvra in product.get('nvras', [])]
        return {
            'name': name,
            'synopsis': synopsis,
            'severity': advisory.get('severity', 'Unknown'),
            'product_name': extract_product_name(synopsis),
            'nvras': filter_and_format_nvras(nvras)
        }
    except requests.RequestException as e:
        print(f"リクエストエラー ({name}): {e}")
        return None
    except ValueError as e:
        print(f"JSONパースエラー ({name}): {e}")
        return None

def parse_arguments():
    parser = argparse.ArgumentParser(description="Rocky Linux Advisory API Client")
    parser.add_argument("-p", choices=["RL8", "RL9"], required=True, help="Product version (RL8 or RL9)")
    parser.add_argument("-t", required=True, help="End date (YYYY-MM-DD)")
    parser.add_argument("-f", required=True, help="Start date (YYYY-MM-DD)")
    parser.add_argument("-s", choices=["IMPORTANT", "CRITICAL"], required=True, help="Severity (IMPORTANT or CRITICAL)")
    return parser.parse_args()

def build_url(args):
    base_url = "https://errata.rockylinux.org/api/v2/advisories"
    product = "Rocky Linux 8" if args.p == "RL8" else "Rocky Linux 9"
    end_date = datetime.strptime(args.t, "%Y-%m-%d")
    start_date = datetime.strptime(args.f, "%Y-%m-%d") - timedelta(days=1)
    severity = f"SEVERITY_{args.s}"
    
    params = {
        "filters.product": product,
        "filters.before": end_date.strftime("%Y-%m-%dT23:59:59.999Z"),
        "filters.after": start_date.strftime("%Y-%m-%dT23:59:59.999Z"),
        "filters.severity": severity,
        "filters.type": "TYPE_SECURITY",
        "filters.fetchRelated": "false",
        "page": "0",
        "limit": "25"
    }
    
    return f"{base_url}?{urllib.parse.urlencode(params)}"

def main():
    args = parse_arguments()
    url = build_url(args)
    advisory_names = get_advisory_names(url)
    
    if advisory_names:
        print("取得されたアドバイザリ:")
        for name in advisory_names:
            details = get_advisory_details(name)
            if details:
                print(f"\nName: {details['name']}")
                print(f"Synopsis: {details['synopsis']}")
                print(f"Severity: {details['severity']}")
                print(f"Product Name: {details['product_name']}")
                print("NVRAs:")
                for nvra in details['nvras']:
                    print(f"  - {nvra}")
    else:
        print("アドバイザリを取得できませんでした。")
        
if __name__ == "__main__":
    main()