import boto3
import argparse
import json
from typing import Optional


def get_cloudfront_distributions(region: str, access_key: str, secret_key: str) -> None:
    """
    List all CloudFront distributions and their details including S3 bucket mappings,
    CloudFront domain names, and custom domains (CNAMEs).
    
    Args:
        region: AWS region (CloudFront is global, but region is needed for client initialization)
        access_key: AWS access key ID
        secret_key: AWS secret access key
    """
    # Initialize CloudFront client with credentials
    # Note: CloudFront is a global service, but we still need to specify a region for the client
    cloudfront_client = boto3.client(
        'cloudfront',
        region_name=region,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key
    )
    
    try:
        # List all CloudFront distributions
        response = cloudfront_client.list_distributions()
        
        # Check if there are any distributions
        if 'DistributionList' not in response or 'Items' not in response['DistributionList']:
            print("No CloudFront distributions found in this AWS account.")
            return
        
        distributions = response['DistributionList']['Items']
        print(f"Found {len(distributions)} CloudFront distribution(s):\n")
        print("=" * 80)
        
        # Process each distribution
        for idx, dist in enumerate(distributions, 1):
            print(f"\n[Distribution #{idx}]")
            print(f"Distribution ID: {dist['Id']}")
            print(f"Domain Name: {dist['DomainName']}")
            print(f"Status: {dist['Status']}")
            print(f"Enabled: {dist['Enabled']}")
            
            # Get custom domain names (CNAMEs)
            if 'Aliases' in dist and 'Items' in dist['Aliases'] and dist['Aliases']['Quantity'] > 0:
                print(f"Custom Domains (CNAMEs):")
                for cname in dist['Aliases']['Items']:
                    print(f"  - {cname}")
            else:
                print("Custom Domains (CNAMEs): None")
            
            # Get origin information
            if 'Origins' in dist and 'Items' in dist['Origins']:
                print(f"\nOrigins ({dist['Origins']['Quantity']}):")
                
                for origin_idx, origin in enumerate(dist['Origins']['Items'], 1):
                    print(f"\n  Origin #{origin_idx}:")
                    print(f"    Origin ID: {origin['Id']}")
                    print(f"    Domain Name: {origin['DomainName']}")
                    
                    # Check if this is an S3 origin
                    if 's3' in origin['DomainName'].lower() and '.amazonaws.com' in origin['DomainName']:
                        # Extract S3 bucket name from domain
                        # Format: bucket-name.s3.region.amazonaws.com or bucket-name.s3.amazonaws.com
                        domain_parts = origin['DomainName'].split('.')
                        bucket_name = domain_parts[0]
                        print(f"    Origin Type: S3 Bucket")
                        print(f"    S3 Bucket Name: {bucket_name}")
                        
                        # Check for S3OriginConfig (indicates S3 origin)
                        if 'S3OriginConfig' in origin:
                            print(f"    Origin Access Identity: {origin['S3OriginConfig'].get('OriginAccessIdentity', 'None')}")
                    else:
                        # This is a custom origin (not S3)
                        print(f"    Origin Type: Custom Origin (Non-S3)")
                        
                        # Display custom origin details
                        if 'CustomOriginConfig' in origin:
                            custom_config = origin['CustomOriginConfig']
                            print(f"    HTTP Port: {custom_config.get('HTTPPort', 'N/A')}")
                            print(f"    HTTPS Port: {custom_config.get('HTTPSPort', 'N/A')}")
                            print(f"    Origin Protocol Policy: {custom_config.get('OriginProtocolPolicy', 'N/A')}")
                            print(f"    Origin SSL Protocols: {custom_config.get('OriginSslProtocols', {}).get('Items', ['N/A'])}")
                            print(f"    Origin Read Timeout: {custom_config.get('OriginReadTimeout', 'N/A')} seconds")
                            print(f"    Origin Keepalive Timeout: {custom_config.get('OriginKeepaliveTimeout', 'N/A')} seconds")
                    
                    # Display connection attempts and timeout
                    if 'ConnectionAttempts' in origin:
                        print(f"    Connection Attempts: {origin['ConnectionAttempts']}")
                    if 'ConnectionTimeout' in origin:
                        print(f"    Connection Timeout: {origin['ConnectionTimeout']} seconds")
                    
                    # Display custom headers if any
                    if 'CustomHeaders' in origin and origin['CustomHeaders']['Quantity'] > 0:
                        print(f"    Custom Headers:")
                        for header in origin['CustomHeaders']['Items']:
                            print(f"      - {header['HeaderName']}: {header['HeaderValue']}")
            
            # Display default cache behavior
            if 'DefaultCacheBehavior' in dist:
                behavior = dist['DefaultCacheBehavior']
                print(f"\nDefault Cache Behavior:")
                print(f"  Target Origin ID: {behavior.get('TargetOriginId', 'N/A')}")
                print(f"  Viewer Protocol Policy: {behavior.get('ViewerProtocolPolicy', 'N/A')}")
                print(f"  Allowed Methods: {behavior.get('AllowedMethods', {}).get('Items', ['N/A'])}")
            
            # Display price class
            if 'PriceClass' in dist:
                print(f"\nPrice Class: {dist['PriceClass']}")
            
            # Display comment/description if available
            if 'Comment' in dist and dist['Comment']:
                print(f"Comment: {dist['Comment']}")
            
            print("\n" + "=" * 80)
        
        # Handle pagination if there are more distributions
        while response.get('DistributionList', {}).get('IsTruncated', False):
            marker = response['DistributionList']['NextMarker']
            response = cloudfront_client.list_distributions(Marker=marker)
            
            if 'DistributionList' in response and 'Items' in response['DistributionList']:
                distributions = response['DistributionList']['Items']
                
                for idx, dist in enumerate(distributions, 1):
                    # Process additional distributions (same logic as above)
                    print(f"\n[Distribution #{idx}]")
                    print(f"Distribution ID: {dist['Id']}")
                    print(f"Domain Name: {dist['DomainName']}")
                    print(f"Status: {dist['Status']}")
                    print(f"Enabled: {dist['Enabled']}")
                    
                    if 'Aliases' in dist and 'Items' in dist['Aliases'] and dist['Aliases']['Quantity'] > 0:
                        print(f"Custom Domains (CNAMEs):")
                        for cname in dist['Aliases']['Items']:
                            print(f"  - {cname}")
                    else:
                        print("Custom Domains (CNAMEs): None")
                    
                    if 'Origins' in dist and 'Items' in dist['Origins']:
                        print(f"\nOrigins ({dist['Origins']['Quantity']}):")
                        
                        for origin_idx, origin in enumerate(dist['Origins']['Items'], 1):
                            print(f"\n  Origin #{origin_idx}:")
                            print(f"    Origin ID: {origin['Id']}")
                            print(f"    Domain Name: {origin['DomainName']}")
                            
                            if 's3' in origin['DomainName'].lower() and '.amazonaws.com' in origin['DomainName']:
                                domain_parts = origin['DomainName'].split('.')
                                bucket_name = domain_parts[0]
                                print(f"    Origin Type: S3 Bucket")
                                print(f"    S3 Bucket Name: {bucket_name}")
                                
                                if 'S3OriginConfig' in origin:
                                    print(f"    Origin Access Identity: {origin['S3OriginConfig'].get('OriginAccessIdentity', 'None')}")
                            else:
                                print(f"    Origin Type: Custom Origin (Non-S3)")
                                
                                if 'CustomOriginConfig' in origin:
                                    custom_config = origin['CustomOriginConfig']
                                    print(f"    HTTP Port: {custom_config.get('HTTPPort', 'N/A')}")
                                    print(f"    HTTPS Port: {custom_config.get('HTTPSPort', 'N/A')}")
                                    print(f"    Origin Protocol Policy: {custom_config.get('OriginProtocolPolicy', 'N/A')}")
                                    print(f"    Origin SSL Protocols: {custom_config.get('OriginSslProtocols', {}).get('Items', ['N/A'])}")
                                    print(f"    Origin Read Timeout: {custom_config.get('OriginReadTimeout', 'N/A')} seconds")
                                    print(f"    Origin Keepalive Timeout: {custom_config.get('OriginKeepaliveTimeout', 'N/A')} seconds")
                    
                    print("\n" + "=" * 80)
                    
    except Exception as e:
        print(f"Error retrieving CloudFront distributions: {str(e)}")


def main():
    """
    Main function to parse arguments and retrieve CloudFront distribution information.
    
    Usage:
        python cloudfrontinfo.py --region us-east-1 --access-key YOUR_KEY --secret-key YOUR_SECRET
    """
    parser = argparse.ArgumentParser(
        description='List all CloudFront distributions with their S3 bucket mappings and domain information'
    )
    parser.add_argument('--region', required=True, help='AWS region (e.g., us-east-1)')
    parser.add_argument('--access-key', required=True, help='AWS access key ID')
    parser.add_argument('--secret-key', required=True, help='AWS secret access key')
    
    args = parser.parse_args()
    
    get_cloudfront_distributions(
        region=args.region,
        access_key=args.access_key,
        secret_key=args.secret_key
    )


if __name__ == '__main__':
    main()
