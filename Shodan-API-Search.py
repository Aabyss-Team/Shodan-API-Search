import argparse, sys
import shodan

def logo():
    logo0 = r'''
   _____ __              __               ___    ____  ____   _____                      __  
  / ___// /_  ____  ____/ /___ _____     /   |  / __ \/  _/  / ___/___  ____ ___________/ /_ 
  \__ \/ __ \/ __ \/ __  / __ `/ __ \   / /| | / /_/ // /    \__ \/ _ \/ __ `/ ___/ ___/ __ \
 ___/ / / / / /_/ / /_/ / /_/ / / / /  / ___ |/ ____// /    ___/ /  __/ /_/ / /  / /__/ / / /
/____/_/ /_/\____/\__,_/\__,_/_/ /_/  /_/  |_/_/   /___/   /____/\___/\__,_/_/   \___/_/ /_/ 
                 [+] Author:AabyssZG          [+] Version: 1.2                             '''
    print(logo0)

def key(api_key):
    api = shodan.Shodan(api_key)
    print('[+] Testing Key: %s' % api_key)
    try:
        info = api.info()
    except Exception:
        print('[-] Key %s is invalid!' % api_key)
        return False,False
    if info['plan'] == 'dev' or info['plan'] == 'edu':
        print('[+] Key %s appears to be valid, and bonus, paid!' % api_key)
        return True,True
    elif info['plan'] == 'oss':
        print('[*] Key %s appears to be valid! Not paid for though!' % api_key)
    else: 
        print(str(info))

def host(api_key, ip):
    api = shodan.Shodan(api_key)
    try:
        results = api.host(ip)
        print("[+] Successful information query\n")
        print("IP: " + str(results['ip_str']))
        print("Hostnames: " + str(results['hostnames']))
        print("IP Country: " + str(results['country_code']))
        print("Prots: " + str(results['ports']))
        print("OS: " + str(results['os']))
        print("Tags: " + str(results['tags']))
        print("Org: " + str(results['org']))
        sys.exit()
    except shodan.APIError as e:
        print('[-] API Error: %s' % e)

def search(api_key, query, max_pages, output_file):
    if (api_key and query and max_pages and output_file) == True:
        print('[-] Please fill in the parameter')
        sys.exit()
    api = shodan.Shodan(api_key)
    file_object = open(output_file, 'a')
    try:
        print("[+] Start information query search\n")
        for page in range(1, max_pages + 1):
            results = api.search(query=query, page=page)
            #print(results)
            print('[+] Results found on page %d. All assets are %s' % (page, results['total']))

            if not results['matches']:
                print('[-] No more results on page %d, stopping.' % page)
                break

            for result in results['matches']:
                file_object.writelines(result['ip_str'] + '\n')

    except shodan.APIError as e:
        print('[-] API Error: %s' % e)
    finally:
        file_object.close()

if __name__ == "__main__":
    logo()
    parser = argparse.ArgumentParser(description='Shodan API search script.')
    parser.add_argument('-k', '--api_key', required=True, help='Your Shodan API key')
    parser.add_argument('-s', '--query', help='Search query')
    parser.add_argument('-p', '--page', type=int, default='1', help='Number of pages to search')
    parser.add_argument('-i', '--host', help='Host you need to query')
    parser.add_argument('-o', '--output', default='ip.txt', help='Output file name (default: ip.txt)')

    args = parser.parse_args()
    if args.query:
        search(args.api_key, args.query, args.page, args.output)
    elif args.host:
        host(args.api_key, args.host)
    elif args.api_key:
        key(args.api_key)
    else: 
        print('[-] Please fill in the parameter')
