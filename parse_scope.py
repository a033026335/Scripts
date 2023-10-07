#The purpose of this script is to help pen testers to easily import postman collections and IP addresses from remediation lead
#and have it export into csv file that can easily re-upload into Restart.
#This will help pen testers save a lot of time when there are large amount of API endpoints that are in scope. 




import json
from tkinter import Tk, filedialog
import socket 
import pandas as pd
import re

# pip install pyfiglet
import pyfiglet

endpoints = []
ip_addresses = []
range_ip_addresses = []
processed_ip_addresses = []
processed_range_ip_addresses = []
final_ip_addresses = []


#Defining parse_test_scope on gathering IP addresses.
def get_ip_addresses():
    print("Enter IP addresses (separate multiple address with spaces):")
    input_ips = input().split()
    for ip in input_ips:
        ip_addresses.append(ip)
    return ip_addresses

#Defining parse_test_scope on converting IP range to a list of IP addresses.
def get_ip_range():
    start_ip = input('Enter the starting IP address: ')
    end_ip = input('Enter the ending IP address: ')
    start_octetes = list(map(int, start_ip.split('.')))
    end_octets = list(map(int, end_ip.split('.')))

    while start_octetes <= end_octets:
        range_ip_addresses.append('.'.join(map(str,start_octetes)))
        start_octetes[-1] += 1
        for i in reversed(range(1,4)):
            if start_octetes[i] == 256:
                start_octetes[i] = 0
                start_octetes[i-1] +=1
    return range_ip_addresses

#Defining parse_test_scope on getting solution name from postman collection.
def sort_by_solution(item):
    #Docstring distriptions.
    """Endpoints Sort Key For Solution

    Args:
        item (_type_): _description_

    Returns:
        str: item.get('Solution')
    """
    return item.get('Solution')

#Defining parse_test_scope on converting IP address to DNS name utilizing socket.
def get_dns_name(ip):
    """Defining parse_test_scope on converting IPs to DNS name.

    Args:
        ip (_type_): _description_

    Returns:
        str: Either valid dns_name or "Not Found"
    """
    try:
        dns_name=socket.gethostbyaddr(ip)[0]
        return dns_name
    except socket.herror:
        return ""

#Defining parse_test_scope on expoerting data to csv using dataframe. 
def export_csv(data, output_file):
    """Defining parse_test_scope of exporting ednpoints to .csv.

    Args:
        data (_type_): _description_
        output_file (_type_): _description_
    """

    # Create a pandas DataFrame
    df = pd.DataFrame(data)

    # Export DataFrame to csv
    df.to_csv(output_file, index=False)

#Defining parse_test_scope on processing main menu selection
def get_user_input():
    """Defining parse_test_scope on wether to import IP ranges or Postman collection.

    Returns:
        str: Users input choice
    """
    print('Select an option:')
    print('1. Import API REST endpoints')
    print('2. Import IP addresses')
    print('q. Quit')
    choice = input('Enter your choice (1 or 2): ')
    if choice not in ['1', '2', 'q']:
        print('Invalid selection.')
    return choice

#Defining parse_test_scope of postman datas.
def process_postman(collection_data, info_name = None):

    #Extracting solution name. We wamt to make sure that we use () instead of [], so when the loop sees no solution name, it doens't cause error, but print out none. 

    if not info_name:
        info_name= collection_data.get('info').get('name')

        # Extract endpoint names and URLs. 
        # 
        # First, it scans the object that name iten and get into the object.
            
    for item in collection_data['item']:

        #It then look for an object that is request. That means it has endpoint. Then, it will gather information about the endpoint and append into appropriate format.
        #It also determine if the endpoint is internal or external proxy and appropriate labels to name.
        if item.get('request'):
            endpoint_name = item['name']
            endpoint_url = item['request']['url']['raw']
            endpoint_DNS = endpoint_url.split('//')[1].lstrip().split('/')[0]

            if "proxy" in endpoint_url:
                endpoint_name = f'External- {endpoint_name}'

            else:
                endpoint_name = f'Internal- {endpoint_name}'

            endpoints.append({ 'Id': '', 'Solution': info_name, 'Request': info_name, 'RequestScopeType': 'Web Application', 'Name': endpoint_name, 'Description': '',
            'CloudProvider': '', 'ResourceParent': '', 'ResourceCollection': '', 'ResourceName': '', 'Region': '', 'Market' :'',
            'Network':'', 'NetworkLocation': '', 'Country': '', 'HostnameOrIPAddress': '', 'NetworkPath': '', 'DnsName': '', 'Port':'',
            'Protocol': '', 'SiteNumber': '', 'StartIP': '', 'EndIP': '', 'ApmId': '', 'SrcrOrSspId': '', 'IsInternallyDeveloped': '',
            'IsSourceCodeAvailableForTheApplication': '', 'ApplicationPath': endpoint_url, 'SourceRepositoryUrl': '', 'DeviceName': '',
            'DevicePath': '', 'OperatingSystem': '', 'Manufacturer': '', 'Model': '', 'IsPhysicallyAccessible': '',
            'IsItPossibleToShipTheDevice': '', 'IsRemoteSupportAvailable': '', 'IsWirelessDevice': '', 'IsExternallyAccessible': '',
            'IsInPCIScope': '', 'IsCreditCardInformationAccepted': '', 'IsDeployedInASecureEnvironment': '', 'IsDocumentationAvailable': '',
            'DocumentationUrl': '', 'IsAuthenticationRequired': '', 'IsAccountLockoutEnabled': '', 'IsAuthenticationDocumentationAvailable': '',
            'AuthenticationDocumentationUrl': '', 'CreatedBy': '', 'CreatedOn': ''})
            
        #Otherwise, if it sees a folder instead of an endpoint, it get into the folder and retrave endpoints and returns it. Besides the folder that name "not in scope"
        elif item.get('name'):
            folder_name= item['name']

            if folder_name == 'not in scope':

                continue
            else:
                process_postman(item,info_name)

    #It returns endpoint outside of the if statement
    return endpoints

#Defining parse_test_scope of IPs.
def process_ip(ip_addresses):

    #Extracting solution name. We wamt to make sure that we use () instead of [], so when the loop sees no solution name, it doens't cause error, but print out none. 

    info_name = input("Enter solution name:")
        # Extract endpoint names and URLs. 
        # 
        # First, it scans the object that name iten and get into the object.

    
    for ip in ip_addresses:
        dns_name= get_dns_name(ip)
        application_path = 'https://'+ip+'/'
        #It then look for an object that is request. That means it has endpoint. Then, it will gather information about the endpoint and append into appropriate format.
        #It also determine if the endpoint is internal or external proxy and appropriate labels to name.

        processed_ip_addresses.append({ 'Id': '', 'Solution': info_name, 'Request': info_name, 'RequestScopeType': 'Networking & Infrastructure', 'Name': ip, 'Description': '',
        'CloudProvider': '', 'ResourceParent': '', 'ResourceCollection': '', 'ResourceName': '', 'Region': '', 'Market' :'',
        'Network':'', 'NetworkLocation': '', 'Country': '', 'HostnameOrIPAddress': ip, 'NetworkPath': '', 'DnsName': dns_name, 'Port':'',
        'Protocol': '', 'SiteNumber': '', 'StartIP': '', 'EndIP': '', 'ApmId': '', 'SrcrOrSspId': '', 'IsInternallyDeveloped': '',
        'IsSourceCodeAvailableForTheApplication': '', 'ApplicationPath': '', 'SourceRepositoryUrl': '', 'DeviceName': '',
        'DevicePath': '', 'OperatingSystem': '', 'Manufacturer': '', 'Model': '', 'IsPhysicallyAccessible': '',
        'IsItPossibleToShipTheDevice': '', 'IsRemoteSupportAvailable': '', 'IsWirelessDevice': '', 'IsExternallyAccessible': '',
        'IsInPCIScope': '', 'IsCreditCardInformationAccepted': '', 'IsDeployedInASecureEnvironment': '', 'IsDocumentationAvailable': '',
        'DocumentationUrl': '', 'IsAuthenticationRequired': '', 'IsAccountLockoutEnabled': '', 'IsAuthenticationDocumentationAvailable': '',
        'AuthenticationDocumentationUrl': '', 'CreatedBy': '', 'CreatedOn': ''})

    return processed_ip_addresses

#Defining parse_test_scope of IPs.
def process_range_ip(range_ip_addresses):

    #Extracting solution name. We wamt to make sure that we use () instead of [], so when the loop sees no solution name, it doens't cause error, but print out none. 

    info_name = input("Enter solution name:")
        # Extract endpoint names and URLs. 
        # 
        # First, it scans the object that name iten and get into the object.

    
    for ip in range_ip_addresses:
        dns_name= get_dns_name(ip)
        start_ip= range_ip_addresses [0]
        end_ip = range_ip_addresses [-1]
        application_path = 'https://'+ip+'/'
        #It then look for an object that is request. That means it has endpoint. Then, it will gather information about the endpoint and append into appropriate format.
        #It also determine if the endpoint is internal or external proxy and appropriate labels to name.

        processed_ip_addresses.append({ 'Id': '', 'Solution': info_name, 'Request': info_name, 'RequestScopeType': 'Networking & Infrastructure', 'Name': ip, 'Description': '',
        'CloudProvider': '', 'ResourceParent': '', 'ResourceCollection': '', 'ResourceName': '', 'Region': '', 'Market' :'',
        'Network':'', 'NetworkLocation': '', 'Country': '', 'HostnameOrIPAddress': ip, 'NetworkPath': '', 'DnsName': dns_name, 'Port':'',
        'Protocol': '', 'SiteNumber': '', 'StartIP': start_ip, 'EndIP': end_ip, 'ApmId': '', 'SrcrOrSspId': '', 'IsInternallyDeveloped': '',
        'IsSourceCodeAvailableForTheApplication': '', 'ApplicationPath': '', 'SourceRepositoryUrl': '', 'DeviceName': '',
        'DevicePath': '', 'OperatingSystem': '', 'Manufacturer': '', 'Model': '', 'IsPhysicallyAccessible': '',
        'IsItPossibleToShipTheDevice': '', 'IsRemoteSupportAvailable': '', 'IsWirelessDevice': '', 'IsExternallyAccessible': '',
        'IsInPCIScope': '', 'IsCreditCardInformationAccepted': '', 'IsDeployedInASecureEnvironment': '', 'IsDocumentationAvailable': '',
        'DocumentationUrl': '', 'IsAuthenticationRequired': '', 'IsAccountLockoutEnabled': '', 'IsAuthenticationDocumentationAvailable': '',
        'AuthenticationDocumentationUrl': '', 'CreatedBy': '', 'CreatedOn': ''})

    return processed_range_ip_addresses

#Defining parse_test_scope of unify menu response on yes or no.
def process_yes_no_menu_prompt(prompt):
    while True:
        user_input =input(f"{prompt} (yes/no): ").strip().lower()

        if user_input == 'yes':
            return True
        elif user_input == 'no':
            return False
        else:
            print('Invalid input. Please enter yes or no')

#Defining parse_test_scope of unify menu response on numeric options.
def process_numeric_menu_prompt(prompt):
    while True:
        try:
            user_input =input(f"{prompt} (1 or 2): ")

            if user_input == '1' or user_input == '2':
                return user_input
            else:
                print('Invalid input. Please enter 1 or 2.')
        except ValueError:
            print('Invalid input. Please enter a valid number.')


def process_curl_commands(collection_data, info_name = None):

    #Extracting solution name. We wamt to make sure that we use () instead of [], so when the loop sees no solution name, it doens't cause error, but print out none. 

    if not info_name:
        info_name= collection_data.get('info').get('name')

        # Extract endpoint names and URLs. 
        # 
        # First, it scans the object that name iten and get into the object.
            
    for item in collection_data['item']:

        #It then look for an object that is request. That means it has endpoint. Then, it will gather information about the endpoint and append into appropriate format.
        #It also determine if the endpoint is internal or external proxy and appropriate labels to name.
        if item.get('request'):
            endpoint_name = item['name']
            endpoint_url = item['request']['url']['raw']
            endpoint_DNS = endpoint_url.split('//')[1].lstrip().split('/')[0]

            if "proxy" in endpoint_url:
                endpoint_name = f'External- {endpoint_name}'

            else:
                endpoint_name = f'Internal- {endpoint_name}'

            endpoints.append({ 'Id': '', 'Solution': info_name, 'Request': info_name, 'RequestScopeType': 'Web Application', 'Name': endpoint_name, 'Description': '',
            'CloudProvider': '', 'ResourceParent': '', 'ResourceCollection': '', 'ResourceName': '', 'Region': '', 'Market' :'',
            'Network':'', 'NetworkLocation': '', 'Country': '', 'HostnameOrIPAddress': endpoint_DNS, 'NetworkPath': endpoint_url, 'DnsName': endpoint_DNS, 'Port':'',
            'Protocol': '', 'SiteNumber': '', 'StartIP': '', 'EndIP': '', 'ApmId': '', 'SrcrOrSspId': '', 'IsInternallyDeveloped': '',
            'IsSourceCodeAvailableForTheApplication': '', 'ApplicationPath': endpoint_url, 'SourceRepositoryUrl': '', 'DeviceName': '',
            'DevicePath': '', 'OperatingSystem': '', 'Manufacturer': '', 'Model': '', 'IsPhysicallyAccessible': '',
            'IsItPossibleToShipTheDevice': '', 'IsRemoteSupportAvailable': '', 'IsWirelessDevice': '', 'IsExternallyAccessible': '',
            'IsInPCIScope': '', 'IsCreditCardInformationAccepted': '', 'IsDeployedInASecureEnvironment': '', 'IsDocumentationAvailable': '',
            'DocumentationUrl': '', 'IsAuthenticationRequired': '', 'IsAccountLockoutEnabled': '', 'IsAuthenticationDocumentationAvailable': '',
            'AuthenticationDocumentationUrl': '', 'CreatedBy': '', 'CreatedOn': ''})
            
        #Otherwise, if it sees a folder instead of an endpoint, it get into the folder and retrave endpoints and returns it. Besides the folder that name "not in scope"
        elif item.get('name'):
            folder_name= item['name']

            if folder_name == 'not in scope':

                continue
            else:
                process_curl_commands(item,info_name)

    #It returns endpoint outside of the if statement
    return endpoints

def reset_global_varialbe_ip():
    global ip_addresses, range_ip_addresses, processed_ip_addresses, processed_range_ip_addresses, final_ip_addresses
    del ip_addresses[:], range_ip_addresses[:], processed_ip_addresses[:], processed_range_ip_addresses[:], final_ip_addresses[:]

def reset_global_varialbe_API():
    global endpoints
    del endpoints[:]

#Postman's sub menu
def choice_one():
    while True:
        print("Choose one option:")
        print("1. Upload Postman collection")
        print("2. upload curl commands")
        prompt_text = "Enter your choice. "
        selected_option = process_numeric_menu_prompt(prompt_text)
        if selected_option == '1':
            window = Tk()
            window.withdraw()
            while True:
                # Open file dialog to select Postman collection file
                print("Select your Postman Collection(s): ")
                file_paths = filedialog.askopenfilenames(filetypes=[("Postman Collection", "*.json")])
                for file_path in file_paths:
                    if not file_path:
                        print("Error: No file selected.")
                        continue

                    with open(file_path, 'r') as file:
                        data = json.load(file)
                        process_postman(data)

                prompt_text = "Do you have more Postman collections?"
                decision = process_yes_no_menu_prompt(prompt_text)

                if decision == False:
                    break
            endpoints.sort(key=sort_by_solution)
        
        elif selected_option == '2':
            window = Tk()
            window.withdraw()
            while True:
                # Open file dialog to select Postman collection file
                print("Select .txt file with curl commands: ")
                file_paths = filedialog.askopenfilenames(filetypes=[("text", "*.txt")])
                for file_path in file_paths:
                    if not file_path:
                        print("Error: No file selected.")
                        continue

                    with open(file_path, 'r') as file:
                        data = json.load(file)
                        process_curl_commands(data)
                prompt_text = "Do you have more .txt file with curl commands?"
                decision = process_yes_no_menu_prompt(prompt_text)

                if decision == False:
                    break
            endpoints.sort(key=sort_by_solution)

        else:
            print("Choose one option:")
            print("1. Upload Postman collection")
            print("2. upload curl commands")
            print('Invalid choice, please enter 1 or 2. \n')


        # Open file dialog to select output CSV file
        output_file = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[("csv file", "*.csv")])

        if output_file:
            export_csv(endpoints, output_file)

            print("Export successful!")
            break
        else:
            print("No output file selected.")

#IP's sub menu
def choice_two():
    ip_addresses = []
    range_ip_addresses = []
    while True:
        print("Choose one option:")
        print("1. Enter individual IP addresses")
        print("2. Enter an IP address range")
        ip_option = input('Enter your choice (1 or 2): ')
        if ip_option == '1':
            ip_addresses = get_ip_addresses()
            # Create the main window
            prompt_text = "Do you have more IP addrsses?"
            decision = process_yes_no_menu_prompt(prompt_text)

            if decision == False:
                break

        elif ip_option == '2':
            range_ip_addresses = get_ip_range()
            prompt_text = "Do you have more IP addrsses?"
            decision = process_yes_no_menu_prompt(prompt_text)

            if decision == False:
                break
        else:
            print('Invalid input. Please enter 1 or 2.')

    window = Tk()
    window.withdraw()
    output_file = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[("csv file", "*.csv")])

    while True:
        if output_file:
            # Export the ip_addresses to CSV
            processed_ip_addresses=process_ip(ip_addresses)
            processed_range_ip_addresses = process_range_ip(range_ip_addresses)
            final_ip_addresses = processed_ip_addresses + processed_range_ip_addresses
            export_csv(final_ip_addresses, output_file)
            print("Export successful!")
            del ip_addresses
            
            break
        else:
            print("Error exporting")

#Main
def main():
    while True:
        reset_global_varialbe_ip()
        reset_global_varialbe_API()
        ascii_banner = pyfiglet.figlet_format("Howdy from Tech Review!!")
        print(ascii_banner)
        choice = get_user_input()
        if choice == '1':
            choice_one()

        elif choice == '2':
            choice_two()

        elif choice == 'q':
            break
        else:
            print('Invalid choice. Please enter either 1 or 2')
        

if __name__ == "__main__":
    main()