import argparse
import os
from dataclasses import dataclass
from typing import Dict, Iterable, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

from azure.identity import DefaultAzureCredential
from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError
from azure.storage.blob import BlobServiceClient


@dataclass(frozen=True)
class CopyStats:
	buckets_total: int
	buckets_processed: int
	objects_total: int
	objects_copied: int
	objects_failed: int
	objects_skipped: int


def _validate_container_name_or_raise(container_name: str) -> None:
	# Azure Blob container naming rules (common subset):
	# - 3-63 characters
	# - lowercase letters, numbers, and hyphen only
	# - must start and end with a letter or number
	if not (3 <= len(container_name) <= 63):
		raise ValueError(
			f"Invalid Azure container name '{container_name}': length must be 3-63 characters"
		)

	if container_name[0] not in "abcdefghijklmnopqrstuvwxyz0123456789" or container_name[-1] not in "abcdefghijklmnopqrstuvwxyz0123456789":
		raise ValueError(
			f"Invalid Azure container name '{container_name}': must start and end with a lowercase letter or number"
		)

	for ch in container_name:
		if ch not in "abcdefghijklmnopqrstuvwxyz0123456789-":
			raise ValueError(
				f"Invalid Azure container name '{container_name}': contains invalid character '{ch}'. "
				"Allowed: lowercase letters, numbers, hyphen."
			)


def _get_bucket_region(s3_client, bucket_name: str) -> str:
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


def _iter_s3_objects(s3_client, bucket_name: str) -> Iterable[dict]:
	paginator = s3_client.get_paginator("list_objects_v2")
	for page in paginator.paginate(Bucket=bucket_name):
		for obj in page.get("Contents", []) or []:
			yield obj


def _ensure_container_exists(blob_service_client: BlobServiceClient, container_name: str) -> None:
	container_client = blob_service_client.get_container_client(container_name)
	try:
		if container_client.exists():
			return
	except Exception:
		# If exists() fails due to transient auth/network, fall back to create attempt.
		pass

	try:
		container_client.create_container()
	except ResourceExistsError:
		return


def _upload_s3_object_to_blob(
	*,
	s3_client,
	bucket_name: str,
	key: str,
	container_client,
	overwrite: bool,
	max_concurrency: int,
) -> None:
	# Stream from S3 directly to Azure (no temp files)
	resp = s3_client.get_object(Bucket=bucket_name, Key=key)
	body = resp["Body"]
	content_length = resp.get("ContentLength")

	try:
		blob_client = container_client.get_blob_client(blob=key)
		if content_length is not None:
			blob_client.upload_blob(
				body,
				overwrite=overwrite,
				length=content_length,
				max_concurrency=max_concurrency,
			)
		else:
			blob_client.upload_blob(
				body,
				overwrite=overwrite,
				max_concurrency=max_concurrency,
			)
	finally:
		try:
			body.close()
		except Exception:
			pass


def copy_all_buckets_s3_to_azure(
	*,
	azure_account_url: str,
	aws_region_hint: Optional[str] = None,
	aws_access_key_id: Optional[str] = None,
	aws_secret_access_key: Optional[str] = None,
	aws_session_token: Optional[str] = None,
	overwrite: bool = True,
	max_concurrency: int = 4,
) -> CopyStats:
	session_kwargs: Dict[str, str] = {}
	if aws_access_key_id:
		session_kwargs["aws_access_key_id"] = aws_access_key_id
	if aws_secret_access_key:
		session_kwargs["aws_secret_access_key"] = aws_secret_access_key
	if aws_session_token:
		session_kwargs["aws_session_token"] = aws_session_token

	# For listing buckets, region is not required; for object operations we use bucket region.
	s3_session = boto3.session.Session(**session_kwargs)
	s3_global_client = s3_session.client("s3", region_name=aws_region_hint or "us-east-1")

	# Azure auth: uses current user / environment (Azure CLI, VS Code, Managed Identity, etc.)
	credential = DefaultAzureCredential(exclude_interactive_browser_credential=False)
	blob_service_client = BlobServiceClient(account_url=azure_account_url, credential=credential)

	buckets_resp = s3_global_client.list_buckets()
	all_buckets = [b["Name"] for b in buckets_resp.get("Buckets", [])]

	# Determine the region to filter on
	region_filter = aws_region_hint
	if not region_filter:
		region_filter = os.environ.get("AWS_REGION")
	# Normalize region name (AWS returns None or 'EU' for some buckets)
	region_filter = (region_filter or "us-east-1").strip()

	filtered_buckets = []
	ignored_buckets = []
	bucket_regions = {}
	for bucket_name in all_buckets:
		bucket_region = _get_bucket_region(s3_global_client, bucket_name)
		bucket_regions[bucket_name] = bucket_region
		if bucket_region == region_filter:
			filtered_buckets.append(bucket_name)
		else:
			ignored_buckets.append((bucket_name, bucket_region))

	buckets_total = len(filtered_buckets)
	buckets_processed = 0
	objects_total = 0
	objects_copied = 0
	objects_failed = 0
	objects_skipped = 0

	s3_client_cache: Dict[str, object] = {}
	container_cache: Dict[str, object] = {}

	for bucket_name in filtered_buckets:
		buckets_processed += 1

		container_name = bucket_name
		_validate_container_name_or_raise(container_name)
		print(f"S3 bucket '{bucket_name}' -> Azure container '{container_name}'")

		_ensure_container_exists(blob_service_client, container_name)
		container_client = container_cache.get(container_name)
		if container_client is None:
			container_client = blob_service_client.get_container_client(container_name)
			container_cache[container_name] = container_client

		bucket_region = bucket_regions[bucket_name]
		s3_bucket_client = s3_client_cache.get(bucket_region)
		if s3_bucket_client is None:
			s3_bucket_client = s3_session.client("s3", region_name=bucket_region)
			s3_client_cache[bucket_region] = s3_bucket_client

		print(f"  Bucket region: {bucket_region}")

		had_any = False
		for obj in _iter_s3_objects(s3_bucket_client, bucket_name):
			had_any = True
			objects_total += 1
			key = obj.get("Key")
			size = obj.get("Size", 0)

			if not key:
				objects_skipped += 1
				continue

			# Skip directory markers
			if key.endswith("/") and size == 0:
				objects_skipped += 1
				continue

			try:
				_upload_s3_object_to_blob(
					s3_client=s3_bucket_client,
					bucket_name=bucket_name,
					key=key,
					container_client=container_client,
					overwrite=overwrite,
					max_concurrency=max_concurrency,
				)
				objects_copied += 1
				if objects_copied % 100 == 0:
					print(f"  Copied {objects_copied} objects so far...")
			except ClientError as e:
				objects_failed += 1
				print(f"  Error copying s3://{bucket_name}/{key}: {e}")
			except Exception as e:
				objects_failed += 1
				print(f"  Error uploading '{key}' to Azure: {e}")

		if not had_any:
			print("  (Bucket empty)")

	# Attach extra info for summary
	stats = CopyStats(
		buckets_total=buckets_total,
		buckets_processed=buckets_processed,
		objects_total=objects_total,
		objects_copied=objects_copied,
		objects_failed=objects_failed,
		objects_skipped=objects_skipped,
	)
	# Attach for summary printing
	stats.copied_buckets = filtered_buckets
	stats.ignored_buckets = ignored_buckets
	stats.region_filter = region_filter
	return stats


def _build_account_url(account_name: Optional[str], account_url: Optional[str]) -> str:
	if account_url:
		return account_url.rstrip("/")
	if not account_name:
		raise ValueError("Provide --account-name or --account-url (or set AZURE_STORAGE_ACCOUNT_NAME / AZURE_STORAGE_ACCOUNT_URL)")
	return f"https://{account_name}.blob.core.windows.net"


def main() -> int:
	parser = argparse.ArgumentParser(
		description="Copy ALL AWS S3 buckets into Azure Blob Storage containers (one container per bucket) using current Azure user credentials"
	)

	# Azure
	parser.add_argument("--account-name", help="Azure Storage account name (or set AZURE_STORAGE_ACCOUNT_NAME)")
	parser.add_argument("--account-url", help="Azure Storage account blob URL (or set AZURE_STORAGE_ACCOUNT_URL)")

	# AWS (optional; boto3 default credential chain works if omitted)
	parser.add_argument("--region", help="AWS region hint used for initial discovery (or set AWS_REGION)")
	parser.add_argument("--access-key", help="AWS access key ID (or set AWS_ACCESS_KEY_ID)")
	parser.add_argument("--secret-key", help="AWS secret access key (or set AWS_SECRET_ACCESS_KEY)")
	parser.add_argument("--session-token", help="AWS session token (or set AWS_SESSION_TOKEN)")

	# Behavior
	parser.add_argument("--no-overwrite", action="store_true", help="Do not overwrite existing blobs")
	parser.add_argument("--max-concurrency", type=int, default=4, help="Parallelism for Azure uploads (default: 4)")

	args = parser.parse_args()

	account_name = args.account_name or os.environ.get("AZURE_STORAGE_ACCOUNT_NAME")
	account_url = args.account_url or os.environ.get("AZURE_STORAGE_ACCOUNT_URL")
	azure_account_url = _build_account_url(account_name, account_url)

	stats = copy_all_buckets_s3_to_azure(
		azure_account_url=azure_account_url,
		aws_region_hint=args.region or os.environ.get("AWS_REGION"),
		aws_access_key_id=args.access_key or os.environ.get("AWS_ACCESS_KEY_ID"),
		aws_secret_access_key=args.secret_key or os.environ.get("AWS_SECRET_ACCESS_KEY"),
		aws_session_token=args.session_token or os.environ.get("AWS_SESSION_TOKEN"),
		overwrite=not args.no_overwrite,
		max_concurrency=max(1, int(args.max_concurrency)),
	)


	print("\nSummary:")
	print(f"- Buckets processed: {stats.buckets_processed}/{stats.buckets_total}")
	print(f"- Objects total: {stats.objects_total}")
	print(f"- Objects copied: {stats.objects_copied}")
	print(f"- Objects skipped: {stats.objects_skipped}")
	print(f"- Objects failed: {stats.objects_failed}")
	print(f"- Region filter: {getattr(stats, 'region_filter', None)}")

	print("\nBuckets copied:")
	for b in getattr(stats, 'copied_buckets', []):
		print(f"  - {b}")
	if not getattr(stats, 'copied_buckets', []):
		print("  (none)")

	print("\nBuckets ignored (not in region):")
	for b, r in getattr(stats, 'ignored_buckets', []):
		print(f"  - {b} (region: {r})")
	if not getattr(stats, 'ignored_buckets', []):
		print("  (none)")

	return 0 if stats.objects_failed == 0 else 2


if __name__ == "__main__":
	raise SystemExit(main())
