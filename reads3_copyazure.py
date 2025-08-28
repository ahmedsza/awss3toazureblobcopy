import boto3
import argparse
import os
import tempfile
from azure.storage.blob import BlobClient
from urllib.parse import urlparse, parse_qs

def upload_to_azure_blob(file_path, file_name, blob_container_sas_url):
    """
    Upload a file to Azure Blob Storage using SAS URL
    """
    try:
        # Parse the SAS URL to correctly handle query parameters
        parsed_url = urlparse(blob_container_sas_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        sas_token = parsed_url.query
        
        # Construct the correct blob URL
        if base_url.endswith('/'):
            blob_url = f"{base_url}{file_name}?{sas_token}"
        else:
            blob_url = f"{base_url}/{file_name}?{sas_token}"
        
        # Create a blob client using the properly formatted URL
        blob_client = BlobClient.from_blob_url(blob_url=blob_url)
        
        # Get file size for progress reporting and chunking decision
        file_size = os.path.getsize(file_path)
        
        # For larger files, use chunked upload with progress reporting
        if file_size > 8 * 1024 * 1024:  # 8 MB threshold
            print(f"Uploading '{file_name}' ({file_size/1024/1024:.2f} MB) to Azure Blob Storage...")
            
            with open(file_path, "rb") as data:
                blob_client.upload_blob(data, overwrite=True, max_concurrency=4)
        else:
            # For smaller files, use standard upload
            with open(file_path, "rb") as data:
                blob_client.upload_blob(data, overwrite=True)
        
        print(f"Successfully uploaded '{file_name}' to Azure Blob Storage")
        return True
    except Exception as e:
        print(f"Error uploading '{file_name}' to Azure: {str(e)}")
        # Consider implementing retries here for certain types of errors
        return False

def list_and_copy_s3_objects(bucket_name, region, access_key, secret_key, blob_container_sas_url):
    """
    List objects in an S3 bucket and copy them to Azure Blob Storage.
    """
    # Initialize the S3 client with credentials and region
    s3_client = boto3.client(
        's3',
        region_name=region,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key
    )
    
    # Create a temporary directory to store downloaded files
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Get the list of objects in the bucket
        response = s3_client.list_objects_v2(Bucket=bucket_name)
        
        # Check if the bucket has any contents
        if 'Contents' not in response:
            print(f"Bucket '{bucket_name}' is empty or doesn't exist.")
            return
        
        # Print the list of objects and copy each to Azure
        print(f"Contents of bucket '{bucket_name}':")
        copied_count = 0
        total_count = 0
        
        def process_objects(objects):
            nonlocal copied_count, total_count
            for obj in objects:
                total_count += 1
                key = obj['Key']
                print(f"- {key} (Size: {obj['Size']} bytes, Last modified: {obj['LastModified']})")
                
                # Skip directories (objects with trailing slash and 0 bytes)
                if key.endswith('/') and obj['Size'] == 0:
                    print(f"  Skipping directory: {key}")
                    continue
                
                # Download the file from S3
                local_path = os.path.join(temp_dir, os.path.basename(key))
                try:
                    s3_client.download_file(bucket_name, key, local_path)
                    
                    # Upload to Azure
                    if upload_to_azure_blob(local_path, os.path.basename(key), blob_container_sas_url):
                        copied_count += 1
                    
                    # Clean up local file
                    os.remove(local_path)
                except Exception as e:
                    print(f"  Error processing '{key}': {str(e)}")
        
        # Process initial set of objects
        process_objects(response['Contents'])
        
        # Handle pagination if there are more than 1000 objects
        while response.get('IsTruncated', False):
            continuation_token = response.get('NextContinuationToken')
            response = s3_client.list_objects_v2(
                Bucket=bucket_name,
                ContinuationToken=continuation_token
            )
            process_objects(response['Contents'])
        
        print(f"\nSummary: Copied {copied_count} out of {total_count} files to Azure Blob Storage")
                
    except Exception as e:
        print(f"Error processing bucket '{bucket_name}': {str(e)}")
    finally:
        # Clean up temporary directory if it's empty
        try:
            os.rmdir(temp_dir)
        except:
            pass

def main():
    parser = argparse.ArgumentParser(description='List objects in an S3 bucket and copy them to Azure Blob Storage')
    parser.add_argument('--bucket', help='Name of the S3 bucket (or set S3_BUCKET env var)')
    parser.add_argument('--region', help='AWS region (e.g., us-east-1) (or set AWS_REGION env var)')
    parser.add_argument('--access-key', help='AWS access key ID (or set AWS_ACCESS_KEY_ID env var)')
    parser.add_argument('--secret-key', help='AWS secret access key (or set AWS_SECRET_ACCESS_KEY env var)')
    parser.add_argument('--azure-sas', 
                        help='Azure Blob Storage container SAS URL (or set AZURE_BLOB_SAS_URL env var)')
    
    args = parser.parse_args()
    
    # Get credentials from environment variables or command line arguments
    bucket_name = args.bucket or os.environ.get('S3_BUCKET')
    region = args.region or os.environ.get('AWS_REGION')
    access_key = args.access_key or os.environ.get('AWS_ACCESS_KEY_ID')
    secret_key = args.secret_key or os.environ.get('AWS_SECRET_ACCESS_KEY')
    azure_sas = args.azure_sas or os.environ.get('AZURE_BLOB_SAS_URL')
    
    # Validate required parameters
    missing_params = []
    if not bucket_name:
        missing_params.append("S3 bucket name (--bucket or S3_BUCKET)")
    if not region:
        missing_params.append("AWS region (--region or AWS_REGION)")
    if not access_key:
        missing_params.append("AWS access key ID (--access-key or AWS_ACCESS_KEY_ID)")
    if not secret_key:
        missing_params.append("AWS secret access key (--secret-key or AWS_SECRET_ACCESS_KEY)")
    if not azure_sas:
        missing_params.append("Azure Blob SAS URL (--azure-sas or AZURE_BLOB_SAS_URL)")
    
    if missing_params:
        print("Error: Missing required parameters:")
        for param in missing_params:
            print(f"- {param}")
        parser.print_help()
        return 1
    
    # Run the main function
    list_and_copy_s3_objects(
        bucket_name=bucket_name,
        region=region,
        access_key=access_key,
        secret_key=secret_key,
        blob_container_sas_url=azure_sas
    )
    
    return 0

if __name__ == '__main__':
    exit(main())