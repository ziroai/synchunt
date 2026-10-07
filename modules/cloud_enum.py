import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from core.utils import save_json, write_file_lines, read_file_lines


class CloudEnumeration:
    """Enumerate cloud resources: S3 buckets, Azure storage, Google Cloud buckets, misconfigurations."""

    def __init__(self, config, runner, logger, output_dir, target):
        self.config = config
        self.runner = runner
        self.logger = logger
        self.output_dir = os.path.join(output_dir, 'cloud_enum')
        self.target = target
        os.makedirs(self.output_dir, exist_ok=True)

    def run_all(self):
        """Enumerate cloud assets."""
        self.logger.phase_banner('CLOUD ASSET ENUMERATION', 7)
        start_time = time.time()

        cloud_assets = {
            's3_buckets': self._enum_s3_buckets(),
            'azure_storage': self._enum_azure_storage(),
            'gcp_buckets': self._enum_gcp_buckets(),
        }

        output_json = os.path.join(self.output_dir, 'cloud_assets.json')
        save_json(cloud_assets, output_json)

        # Summary
        summary_lines = []
        for bucket in cloud_assets.get('s3_buckets', []):
            summary_lines.append(f"S3: {bucket['name']} | accessible={bucket.get('accessible', False)}")
        for storage in cloud_assets.get('azure_storage', []):
            summary_lines.append(f"Azure: {storage['name']} | accessible={storage.get('accessible', False)}")
        for bucket in cloud_assets.get('gcp_buckets', []):
            summary_lines.append(f"GCP: {bucket['name']} | accessible={bucket.get('accessible', False)}")
        
        write_file_lines(os.path.join(self.output_dir, 'cloud_summary.txt'), summary_lines)

        duration = time.time() - start_time
        total = sum(len(cloud_assets.get(k, [])) for k in cloud_assets)
        self.logger.result(f'Cloud enumeration complete: {total} assets found in {duration:.1f}s')
        return output_json

    def _enum_s3_buckets(self):
        """Enumerate S3 buckets."""
        self.logger.info('Enumerating S3 buckets...')
        buckets = []
        
        # Generate bucket name variations
        bucket_names = self._generate_bucket_names()
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._check_s3_bucket, name): name for name in bucket_names}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        buckets.append(result)
                except Exception:
                    pass

        self.logger.found(f'S3: {len(buckets)} buckets found')
        return buckets

    def _check_s3_bucket(self, bucket_name):
        """Check if S3 bucket exists and is accessible."""
        try:
            # Try to access bucket listing
            url = f'https://{bucket_name}.s3.amazonaws.com/'
            response = requests.head(url, timeout=5)
            if response.status_code in (200, 403):
                return {
                    'name': bucket_name,
                    'accessible': response.status_code == 200,
                    'status_code': response.status_code
                }
        except Exception:
            pass
        return None

    def _enum_azure_storage(self):
        """Enumerate Azure Storage accounts."""
        self.logger.info('Enumerating Azure Storage...')
        accounts = []
        
        storage_names = self._generate_storage_names()
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._check_azure_storage, name): name for name in storage_names}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        accounts.append(result)
                except Exception:
                    pass

        self.logger.found(f'Azure: {len(accounts)} accounts found')
        return accounts

    def _check_azure_storage(self, account_name):
        """Check Azure Storage account."""
        try:
            url = f'https://{account_name}.blob.core.windows.net/'
            response = requests.head(url, timeout=5)
            if response.status_code in (200, 403):
                return {
                    'name': account_name,
                    'accessible': response.status_code == 200,
                    'status_code': response.status_code
                }
        except Exception:
            pass
        return None

    def _enum_gcp_buckets(self):
        """Enumerate Google Cloud Storage buckets."""
        self.logger.info('Enumerating GCP buckets...')
        buckets = []
        
        bucket_names = self._generate_bucket_names()
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._check_gcp_bucket, name): name for name in bucket_names}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        buckets.append(result)
                except Exception:
                    pass

        self.logger.found(f'GCP: {len(buckets)} buckets found')
        return buckets

    def _check_gcp_bucket(self, bucket_name):
        """Check GCP bucket accessibility."""
        try:
            url = f'https://storage.googleapis.com/{bucket_name}/'
            response = requests.head(url, timeout=5)
            if response.status_code in (200, 403):
                return {
                    'name': bucket_name,
                    'accessible': response.status_code == 200,
                    'status_code': response.status_code
                }
        except Exception:
            pass
        return None

    def _generate_bucket_names(self):
        """Generate bucket name variations."""
        variations = []
        base = self.target.replace('.', '-').replace('_', '-')[:50]
        
        for suffix in ['', '-backup', '-data', '-prod', '-dev', '-staging', '-public', '-assets', '-files', '-documents']:
            variations.append(f"{base}{suffix}")
        
        return variations[:20]

    def _generate_storage_names(self):
        """Generate storage account name variations."""
        variations = []
        base = self.target.replace('.', '').replace('-', '')[:20]
        
        for suffix in ['', 'backup', 'data', 'prod', 'dev', 'staging', 'public', 'assets']:
            variations.append(f"{base}{suffix}")
        
        return variations[:20]
