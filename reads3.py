import boto3
import argparse

def list_s3_objects(bucket_name, region, access_key, secret_key):
    """
    List objects in an S3 bucket using provided credentials and region.
    """
    # Initialize the S3 client with credentials and region
    s3_client = boto3.client(
        's3',
        region_name=region,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key
    )
    
    try:
        # Get the list of objects in the bucket
        response = s3_client.list_objects_v2(Bucket=bucket_name)
        
        # Check if the bucket has any contents
        if 'Contents' not in response:
            print(f"Bucket '{bucket_name}' is empty or doesn't exist.")
            return
        
        # Print the list of objects
        print(f"Contents of bucket '{bucket_name}':")
        for obj in response['Contents']:
            print(f"- {obj['Key']} (Size: {obj['Size']} bytes, Last modified: {obj['LastModified']})")
        
        # Handle pagination if there are more than 1000 objects
        while response.get('IsTruncated', False):
            continuation_token = response.get('NextContinuationToken')
            response = s3_client.list_objects_v2(
                Bucket=bucket_name,
                ContinuationToken=continuation_token
            )
            for obj in response['Contents']:
                print(f"- {obj['Key']} (Size: {obj['Size']} bytes, Last modified: {obj['LastModified']})")
                
    except Exception as e:
        print(f"Error listing objects in bucket '{bucket_name}': {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='List objects in an S3 bucket')
    parser.add_argument('--bucket', required=True, help='Name of the S3 bucket')
    parser.add_argument('--region', required=True, help='AWS region (e.g., us-east-1)')
    parser.add_argument('--access-key', required=True, help='AWS access key ID')
    parser.add_argument('--secret-key', required=True, help='AWS secret access key')
    
    args = parser.parse_args()
    
    list_s3_objects(
        bucket_name=args.bucket,
        region=args.region,
        access_key=args.access_key,
        secret_key=args.secret_key
    )

if __name__ == '__main__':
    main()