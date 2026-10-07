import os
import re
import time

from core.utils import read_file_lines, save_json, write_file_lines


class FindingPrioritizer:
    """Score, rank, and deduplicate findings from recon output."""

    # Severity scoring weights
    KEYWORD_WEIGHTS = {
        'critical': {
            'keywords': [
                'aws_secret_access_key', 'begin rsa private key', 'begin openssh private key',
                'begin pgp private key block', 'private_key', 'db_password', 'root_password',
                'admin_password', 'secret_key', 'access_token', 'refresh_token', 'jwt'
            ],
            'weight': 100
        },
        'high': {
            'keywords': [
                'sql injection', 'xss', 'ssrf', 'remote code execution', 'rce', 'idor',
                'authentication bypass', 'authorization bypass', 'path traversal', 'lfi',
                'command injection', 'xxe', 'xml external entity', 'crlf injection'
            ],
            'weight': 65
        },
        'medium': {
            'keywords': [
                'open redirect', 'csrf', 'cors misconfiguration', 'clickjacking',
                'insecure deserialization', 'weak cryptography', 'hardcoded credentials',
                'exposed admin panel', 'exposed debug info', 'exposed swagger ui',
                'exposed graphql endpoint', 's3 bucket publicly accessible'
            ],
            'weight': 40
        },
        'low': {
            'keywords': [
                'information disclosure', 'directory listing', 'missing security headers',
                'weak password policy', 'missing rate limiting', 'verbose error messages'
            ],
            'weight': 15
        }
    }

    def __init__(self, config, runner, logger, output_dir):
        self.config = config
        self.runner = runner
        self.logger = logger
        self.output_dir = output_dir
        self.findings_dir = os.path.join(output_dir, 'findings_prioritized')
        os.makedirs(self.findings_dir, exist_ok=True)

    def run_all(self):
        """Collect and prioritize all findings."""
        self.logger.phase_banner('FINDING PRIORITIZATION & TRIAGE', 9)
        start_time = time.time()

        files_to_scan = self._collect_finding_files()
        self.logger.info(f'Scanning {len(files_to_scan)} result files for prioritization...')

        scored = []
        for file_path in files_to_scan:
            try:
                for line in read_file_lines(file_path):
                    score_info = self._score_line(line, file_path)
                    if score_info['score'] > 0:
                        scored.append(score_info)
            except Exception as e:
                self.logger.debug(f'Error scanning {file_path}: {e}')

        # Sort by score
        scored.sort(key=lambda x: x['score'], reverse=True)

        # Deduplicate similar findings
        scored = self._dedupe_similar(scored)

        # Save outputs
        output_json = os.path.join(self.findings_dir, 'prioritized_findings.json')
        save_json(scored, output_json)

        # Summary files by severity
        by_severity = {}
        for item in scored:
            sev = item['severity']
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(item)

        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in by_severity:
                summary_lines = [
                    f"[{item['score']:3d}] {item['file']:30s} | {item['finding'][:80]}"
                    for item in by_severity[severity]
                ]
                write_file_lines(
                    os.path.join(self.findings_dir, f'findings_{severity.lower()}.txt'),
                    summary_lines
                )

        duration = time.time() - start_time
        self.logger.result(f'Prioritized {len(scored)} findings in {duration:.1f}s')
        self.logger.info(
            f"  CRITICAL: {len(by_severity.get('CRITICAL', []))} | "
            f"HIGH: {len(by_severity.get('HIGH', []))} | "
            f"MEDIUM: {len(by_severity.get('MEDIUM', []))} | "
            f"LOW: {len(by_severity.get('LOW', []))}"
        )
        return output_json

    def _collect_finding_files(self):
        """Collect all result files from scan output."""
        candidates = []
        exclude_dirs = ['findings_prioritized', 'reports', 'logs']
        for root, dirs, files in os.walk(self.output_dir):
            # Skip excluded dirs
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for filename in files:
                if filename.endswith(('.txt', '.json', '.log')):
                    path = os.path.join(root, filename)
                    # Skip certain files
                    if any(skip in path for skip in ['summary', 'all_', 'merged']):
                        continue
                    candidates.append(path)
        return candidates

    def _score_line(self, line, source_file):
        """Score a line based on keywords and patterns."""
        text = line.lower()
        score = 0
        severity = 'LOW'
        matched_keywords = []

        # Check each severity level
        for sev_level in ['critical', 'high', 'medium', 'low']:
            sev_info = self.KEYWORD_WEIGHTS[sev_level]
            for keyword in sev_info['keywords']:
                if keyword.lower() in text:
                    score += sev_info['weight']
                    matched_keywords.append(keyword)
                    if score >= self.KEYWORD_WEIGHTS['critical']['weight'] and severity == 'LOW':
                        severity = 'CRITICAL'
                    elif score >= self.KEYWORD_WEIGHTS['high']['weight'] and severity in ['LOW', 'MEDIUM']:
                        severity = 'HIGH'
                    elif score >= self.KEYWORD_WEIGHTS['medium']['weight'] and severity == 'LOW':
                        severity = 'MEDIUM'

        # Boost for URLs
        if re.search(r'https?://', line):
            score += 8

        # Boost for admin/sensitive paths
        if re.search(r'(?i)(/admin|/login|/dashboard|/swagger|/graphql|/api|/.well-known)', line):
            score += 12

        # Boost for credentials patterns
        if re.search(r'(?i)(password|token|secret|key|credential|auth)\s*[:=]', line):
            score += 15

        # Boost for AWS, GCP, Azure patterns
        if re.search(r'(?i)(aws|gcp|azure|s3://|gs://|azure-|appspot)', line):
            score += 10

        # Set severity based on final score
        if score >= 100:
            severity = 'CRITICAL'
        elif score >= 60:
            severity = 'HIGH'
        elif score >= 30:
            severity = 'MEDIUM'
        else:
            severity = 'LOW'

        return {
            'source': os.path.relpath(source_file, self.output_dir),
            'finding': line[:300],
            'score': score,
            'severity': severity,
            'keywords': matched_keywords[:5]
        }

    def _dedupe_similar(self, findings):
        """Remove similar/duplicate findings."""
        deduped = []
        seen_hashes = set()
        for item in findings:
            # Simple dedup: hash the finding text
            finding_hash = hash(item['finding'][:50])
            if finding_hash not in seen_hashes:
                seen_hashes.add(finding_hash)
                deduped.append(item)
        return deduped
