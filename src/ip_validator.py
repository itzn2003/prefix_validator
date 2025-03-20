"""
IP Prefix Validator Module

This module validates IP prefixes using the RIPE NCC RPKI validator API.
It communicates directly with the Routinator service via HTTP requests.
"""

import requests
import csv
import time
import os

def read_ip_addresses(file_path):
    """
    Read IP addresses from a file, one per line.
    
    Args:
        file_path (str): Path to the file containing IP addresses
        
    Returns:
        list: List of IP addresses
    """
    try:
        with open(file_path, 'r') as file:
            ip_addresses = [line.strip() for line in file if line.strip()]
        return ip_addresses
    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
        return []
    except Exception as e:
        print(f"An error occurred: {e}")
        return []

def validate_ip_address(prefix, asn):
    """
    Validate a single IP prefix against an ASN using the RPKI validator API.
    
    Args:
        prefix (str): IP prefix to validate (e.g., "193.0.0.0/21")
        asn (int): Autonomous System Number
        
    Returns:
        dict: Validation result with status, description, etc.
    """
    # Using the form-friendly API endpoint
    url = f"https://rpki-validator.ripe.net/validity?asn={asn}&prefix={prefix}"
    
    try:
        # Send the request to the API
        response = requests.get(url, timeout=10)
        
        # Check if the request was successful
        if response.status_code == 200:
            api_response = response.json()
            
            # Format the response to match our expected structure
            result = {
                "IP_Address": prefix,
                "Validation_Status": api_response.get("validated_route", {}).get("validity", {}).get("state", "unknown"),
                "ASN": asn
            }
            
            # Add detailed description based on validation status
            if result["Validation_Status"] == "valid":
                result["Description"] = "The announcement matches a ROA and is valid"
            elif result["Validation_Status"] == "invalid_asn":
                result["Description"] = "There is a ROA with the same (or covering) prefix, but a different ASN"
            elif result["Validation_Status"] == "invalid_length":
                result["Description"] = "The announcement's prefix length is greater than the ROA's maximum length"
            elif result["Validation_Status"] == "unknown":
                result["Description"] = "No ROA found for the announcement"
            else:
                result["Description"] = api_response.get("reason", "")
            
            # Add any VRPs that led to this validation result
            vrps = api_response.get("validated_route", {}).get("validity", {}).get("VRPs", {})
            if vrps:
                matched_vrps = vrps.get("matched", [])
                unmatched_vrps = vrps.get("unmatched_asn", []) + vrps.get("unmatched_length", [])
                
                if matched_vrps:
                    result["Matched_VRPs"] = ", ".join([f"{v.get('prefix', '')}/{v.get('max_length', '')} AS{v.get('asn', '')}" for v in matched_vrps])
                
                if unmatched_vrps:
                    result["Unmatched_VRPs"] = ", ".join([f"{v.get('prefix', '')}/{v.get('max_length', '')} AS{v.get('asn', '')}" for v in unmatched_vrps])
            
            return result
        else:
            print(f"API Error: Status code {response.status_code} for prefix {prefix}")
            return {
                "IP_Address": prefix,
                "Validation_Status": "error",
                "Description": f"API Error: Status code {response.status_code}",
                "ASN": asn
            }
            
    except requests.exceptions.RequestException as e:
        print(f"Request failed for prefix {prefix}: {str(e)}")
        return {
            "IP_Address": prefix,
            "Validation_Status": "error",
            "Description": f"Request failed: {str(e)}",
            "ASN": asn
        }

def validate_ip_addresses(ip_list, asn, output_file=None, batch_size=10, delay=1):
    """
    Validate multiple IP addresses using the RPKI validator API.
    
    Args:
        ip_list (list): List of IP addresses to validate
        asn (int): Autonomous System Number
        output_file (str, optional): Path to save the CSV results
        batch_size (int, optional): Number of IPs to process before pause
        delay (float, optional): Delay in seconds between batches
        
    Returns:
        list: List of validation results
    """
    results = []
    
    print(f"Starting validation of {len(ip_list)} IP prefixes against ASN {asn}...")
    print(f"Using RIPE NCC RPKI validator API")
    
    for i, ip in enumerate(ip_list):
        # Validate the IP address
        result = validate_ip_address(ip, asn)
        
        # Store the result
        results.append(result)
        
        # Print progress
        print(f"Validated [{i+1}/{len(ip_list)}] {ip}: {result['Validation_Status']}")
        
        # Pause after each batch to avoid overloading the API
        if (i + 1) % batch_size == 0 and i < len(ip_list) - 1:
            print(f"Processed {i+1} prefixes. Pausing for {delay} second(s)...")
            time.sleep(delay)
    
    # Save results to CSV if output file is specified
    if output_file and results:
        save_results_to_csv(results, output_file)
    
    return results

def save_results_to_csv(results, output_file):
    """
    Save validation results to a CSV file with trimmed output.
    
    Args:
        results (list): List of validation result dictionaries
        output_file (str): Path to the output CSV file
    """
    try:
        # Ensure the output directory exists
        output_dir = os.path.dirname(os.path.abspath(output_file))
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        # Use only the specified fields
        ordered_fields = ["IP_Address", "Validation_Status", "ASN", "Matched_VRPs"]
        
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=ordered_fields)
            writer.writeheader()
            
            # Write only the specified fields for each result
            for result in results:
                trimmed_result = {
                    "IP_Address": result.get("IP_Address", ""),
                    "Validation_Status": result.get("Validation_Status", ""),
                    "ASN": result.get("ASN", ""),
                    "Matched_VRPs": result.get("Matched_VRPs", "")
                }
                writer.writerow(trimmed_result)
        
        print(f"Results saved to {output_file}")
        return True
    except Exception as e:
        print(f"Error saving to CSV: {e}")
        return False

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Validate IP prefixes using RPKI validator API.')
    parser.add_argument('file_path', help='Path to the file containing IP prefixes')
    parser.add_argument('--asn', type=int, required=True, help='Autonomous System Number')
    parser.add_argument('-o', '--output', help='Path to the output CSV file')
    parser.add_argument('--batch-size', type=int, default=10, 
                        help='Number of IPs to process before pause (default: 10)')
    parser.add_argument('--delay', type=float, default=1.0,
                        help='Delay in seconds between batches (default: 1.0)')
    
    args = parser.parse_args()
    
    ip_list = read_ip_addresses(args.file_path)
    print(f"Total IP Addresses: {len(ip_list)}")
    
    if ip_list:
        validate_ip_addresses(ip_list, args.asn, args.output, args.batch_size, args.delay)
        return True
    
    return False

if __name__ == "__main__":
    main()