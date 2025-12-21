import argparse
import os
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError


def format_size(size_bytes: int) -> str:
    """
    Format byte size to human-readable format.
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


def get_bucket_region(s3_client, bucket_name: str) -> str:
    """
    Get the region of an S3 bucket.
    """
    try:
        resp = s3_client.get_bucket_location(Bucket=bucket_name)
        loc = resp.get("LocationConstraint")
        if not loc:
            return "us-east-1"
        if loc == "EU":
            return "eu-west-1"
        return loc
    except ClientError:
        return "us-east-1"


def get_bucket_info(s3_client, bucket_name: str, bucket_region: str) -> Dict[str, any]:
    """
    Get information about an S3 bucket including object count and total size.
    """
    # Create a region-specific client for this bucket
    s3_regional_client = boto3.client(
        's3',
        region_name=bucket_region,
        aws_access_key_id=s3_client._request_signer._credentials.access_key,
        aws_secret_access_key=s3_client._request_signer._credentials.secret_key,
        aws_session_token=s3_client._request_signer._credentials.token
    )
    
    object_count = 0
    total_size = 0
    
    try:
        paginator = s3_regional_client.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=bucket_name):
            contents = page.get('Contents', [])
            for obj in contents:
                object_count += 1
                total_size += obj.get('Size', 0)
        
        return {
            'bucket_name': bucket_name,
            'region': bucket_region,
            'object_count': object_count,
            'total_size_bytes': total_size,
            'total_size_formatted': format_size(total_size),
            'error': None
        }
    except ClientError as e:
        return {
            'bucket_name': bucket_name,
            'region': bucket_region,
            'object_count': 0,
            'total_size_bytes': 0,
            'total_size_formatted': '0 B',
            'error': str(e)
        }


def enumerate_s3_buckets(
    aws_region_hint: Optional[str] = None,
    aws_access_key_id: Optional[str] = None,
    aws_secret_access_key: Optional[str] = None,
    aws_session_token: Optional[str] = None
) -> List[Dict[str, any]]:
    """
    Enumerate all S3 buckets and get information about each one.
    """
    session_kwargs: Dict[str, str] = {}
    if aws_access_key_id:
        session_kwargs["aws_access_key_id"] = aws_access_key_id
    if aws_secret_access_key:
        session_kwargs["aws_secret_access_key"] = aws_secret_access_key
    if aws_session_token:
        session_kwargs["aws_session_token"] = aws_session_token
    
    # Create S3 client for listing buckets
    s3_session = boto3.session.Session(**session_kwargs)
    s3_client = s3_session.client("s3", region_name=aws_region_hint or "us-east-1")
    
    # List all buckets
    try:
        buckets_resp = s3_client.list_buckets()
        buckets = [b["Name"] for b in buckets_resp.get("Buckets", [])]
    except ClientError as e:
        print(f"Error listing buckets: {e}")
        return []
    
    print(f"Found {len(buckets)} bucket(s)\n")
    
    bucket_info_list = []
    
    for bucket_name in buckets:
        print(f"Processing bucket: {bucket_name}")
        
        # Get bucket region
        bucket_region = get_bucket_region(s3_client, bucket_name)
        print(f"  Region: {bucket_region}")
        
        # Get bucket information
        bucket_info = get_bucket_info(s3_client, bucket_name, bucket_region)
        bucket_info_list.append(bucket_info)
        
        if bucket_info['error']:
            print(f"  Error: {bucket_info['error']}")
        else:
            print(f"  Object count: {bucket_info['object_count']}")
            print(f"  Total size: {bucket_info['total_size_formatted']} ({bucket_info['total_size_bytes']} bytes)")
        
        print()
    
    return bucket_info_list


def print_summary(bucket_info_list: List[Dict[str, any]]) -> None:
    """
    Print a summary of all buckets.
    """
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"{'Bucket Name':<30} {'Region':<15} {'Objects':<12} {'Size':<20}")
    print("-" * 80)
    
    total_objects = 0
    total_size = 0
    
    for info in bucket_info_list:
        if info['error']:
            print(f"{info['bucket_name']:<30} {info['region']:<15} {'ERROR':<12} {info['error'][:20]:<20}")
        else:
            print(f"{info['bucket_name']:<30} {info['region']:<15} {info['object_count']:<12} {info['total_size_formatted']:<20}")
            total_objects += info['object_count']
            total_size += info['total_size_bytes']
    
    print("-" * 80)
    print(f"{'TOTAL':<30} {'':<15} {total_objects:<12} {format_size(total_size):<20}")
    print("=" * 80)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Enumerate all AWS S3 buckets and display object count and total size for each"
    )
    
    # AWS credentials (optional; boto3 default credential chain works if omitted)
    parser.add_argument("--region", help="AWS region hint for initial discovery (or set AWS_REGION)")
    parser.add_argument("--access-key", help="AWS access key ID (or set AWS_ACCESS_KEY_ID)")
    parser.add_argument("--secret-key", help="AWS secret access key (or set AWS_SECRET_ACCESS_KEY)")
    parser.add_argument("--session-token", help="AWS session token (or set AWS_SESSION_TOKEN)")
    
    args = parser.parse_args()
    
    # Get credentials from arguments or environment variables
    aws_region = args.region or os.environ.get("AWS_REGION")
    aws_access_key = args.access_key or os.environ.get("AWS_ACCESS_KEY_ID")
    aws_secret_key = args.secret_key or os.environ.get("AWS_SECRET_ACCESS_KEY")
    aws_session_token = args.session_token or os.environ.get("AWS_SESSION_TOKEN")
    
    # Enumerate buckets
    bucket_info_list = enumerate_s3_buckets(
        aws_region_hint=aws_region,
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        aws_session_token=aws_session_token
    )
    
    # Print summary
    if bucket_info_list:
        print_summary(bucket_info_list)
    else:
        print("No buckets found or unable to access AWS S3.")
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
