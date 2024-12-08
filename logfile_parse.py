# Sample log file parser which will parse the log file, get the IP addressed with their frequency,
#Most accessed End-Point 
#Failed Login aatempts with frequency and export the data to a csv file 

import re
import csv
import collections
    

# Access End-poitns Reader

def log_endpoint_reader(filename):

    # Get all End-points from the log file
    with open(filename) as f:
        log = f.read()
        endpoint_pattern = r'\"GET (/[^\s]*) HTTP' 
        endpoint_list = re.findall(endpoint_pattern, log)
        return endpoint_list 


# Get total count of End-point count
def count_endpoint(endpoint_list):
    return collections.Counter(endpoint_list)
    

#Write total  frequency of end-points to csv file in descending order
def write_endpoint_to_csv(counter):
    with open('log_analysis_results.csv', 'a') as csvfile:
        writer = csv.writer(csvfile)
        header1 = ['Most Accessed Endpoint:']
        header2 = ['Endpoint','Access Count']
        writer.writerow(header1)
        writer.writerow(header2)
        for item,count in counter.most_common():      
            writer.writerow((item,'(Accessed ',counter[item],'times)'))      #print most accessed end-point
            break
	

#Print total frequency of End-point in descending order
def print_endpoint_to_terminal(filename):
        counter = count_endpoint(log_endpoint_reader(filename))
        print('Most Frequently Accessed Endpoint:')
        for item,count in counter.most_common():
        	print(item,'\t','(Accessed',count,'times)')    #print most accessed end-point
        	break
 
    

# To read the log file and send the list of IPS
def log_file_reader(filename):

    # Get all IP addresses from the log file
    with open(filename) as f:
        log = f.read()
        regex = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        ip_list = re.findall(regex, log)
        return ip_list

    
# Get total count of IPs
def count_ip(ip_list):
    return collections.Counter(ip_list)

# Write total frequency of IPs to csv file in descending order
def write_to_csv(counter):
    with open('log_analysis_results.csv', 'w') as csvfile:
        writer = csv.writer(csvfile)
        header1 = ['Requests per IP:']
        header2 = ['IP Address', 'Request Count']
        writer.writerow(header1)
        writer.writerow(header2)
        for item,count in counter.most_common():
            writer.writerow((item, counter[item]))
          
            
#Print total frequency of IPs in descending order
def print_to_terminal(filename):
        counter = count_ip(log_file_reader(filename))
        print('IP Address','\t\t\t\t','Request Count')
        for item,count in counter.most_common():
        	print(item,'\t\t\t\t', count) 


#Extracts IP addresses associated with failed login attempts from a log file.

def extract_failed_login_ips(log_file_path):
    
    failed_ips_list = list()

    with open(log_file_path, 'r') as log_file:
        for line in log_file:
            if "Invalid credential" in line:  # Search for ip where error message occured
                ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
                ip_match = re.findall(ip_pattern, line)
                if ip_match:
                    failed_ips_list[0:0] = ip_match
    return failed_ips_list


# Get total count of failed_ips 
def count_failed_ips(failed_ips_list):
    return collections.Counter(failed_ips_list)

#Write total IPs and its failed login attempt to csv file in descending order
def write_failed_ips_to_csv(counter):
    with open('log_analysis_results.csv', 'a') as csvfile:
        writer = csv.writer(csvfile)
        header1 = ['Suspicious Activity:']
        header2 = ['IP Address', 'Failed Login Count']
        writer.writerow(header1)
        writer.writerow(header2)
        for item,count in counter.most_common():
            writer.writerow((item, counter[item]))           
            
#Print total IPs and its failed login attempt 
def print_failed_ips_to_terminal(filename):
        counter = count_failed_ips(extract_failed_login_ips(log_file_path))
        print('Suspicious Activity Detected:')
        print('IP Address','\t\t\t\t','Failed Login Attempts')
        for item,count in counter.most_common():
        	print(item,'\t\t\t\t', count) 



if __name__ == "__main__":

# Write IP Frequency to CSV
    write_to_csv(count_ip(log_file_reader('sample.log'))) 

# Print IP Frequency to Terminal    
    print_to_terminal('sample.log')
    
# Replace with your log file path for access point count
    
    log_file_path = "sample.log" 
    
# Write End-Point to CSV     
    write_endpoint_to_csv(count_endpoint(log_endpoint_reader(log_file_path)))
    
# Print End-Point to Terminal    
    print_endpoint_to_terminal(log_file_path)
   
#Write failed logins to CSV
    write_failed_ips_to_csv(count_failed_ips(extract_failed_login_ips(log_file_path)))

# Print Failed logins to Terminal
    print_failed_ips_to_terminal(log_file_path)
   
