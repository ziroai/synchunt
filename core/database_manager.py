"""
Synchunt - Database Manager
Handles result storage, correlation, and deduplication using SQLite.
"""

import json
import os
import sqlite3
from datetime import datetime
from typing import List, Dict, Any


class DatabaseManager:
    """Manage scan results in SQLite for correlation and analysis."""

    def __init__(self, output_dir):
        self.db_path = os.path.join(output_dir, 'synchunt_results.db')
        self.init_db()

    def init_db(self):
        """Initialize database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Hosts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY,
                target TEXT,
                host TEXT UNIQUE,
                url TEXT,
                ips TEXT,
                status_code INTEGER,
                title TEXT,
                tech_stack TEXT,
                exposures TEXT,
                last_seen TIMESTAMP
            )
        ''')

        # Subdomains table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY,
                target TEXT,
                subdomain TEXT UNIQUE,
                discovered_by TEXT,
                is_live BOOLEAN,
                ips TEXT,
                last_seen TIMESTAMP
            )
        ''')

        # Ports and services table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY,
                host TEXT,
                port INTEGER,
                protocol TEXT,
                service TEXT,
                version TEXT,
                last_seen TIMESTAMP
            )
        ''')

        # URLs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS urls (
                id INTEGER PRIMARY KEY,
                target TEXT,
                url TEXT UNIQUE,
                method TEXT,
                status_code INTEGER,
                has_params BOOLEAN,
                discovered_by TEXT,
                last_seen TIMESTAMP
            )
        ''')

        # Endpoints table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY,
                url TEXT,
                path TEXT,
                method TEXT,
                params TEXT,
                api_type TEXT,
                last_seen TIMESTAMP
            )
        ''')

        # Findings/Vulnerabilities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY,
                target TEXT,
                severity TEXT,
                type TEXT,
                description TEXT,
                evidence TEXT,
                affected_asset TEXT,
                score INTEGER,
                confidence INTEGER,
                exploitable BOOLEAN,
                deduplication_hash TEXT UNIQUE,
                last_seen TIMESTAMP
            )
        ''')

        # Secrets/Credentials table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY,
                target TEXT,
                secret_type TEXT,
                secret_value TEXT,
                source_file TEXT,
                source_url TEXT,
                severity TEXT,
                deduplication_hash TEXT UNIQUE,
                last_seen TIMESTAMP
            )
        ''')

        # JavaScript analysis table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS js_analysis (
                id INTEGER PRIMARY KEY,
                target TEXT,
                js_file TEXT,
                endpoints TEXT,
                secrets TEXT,
                comments TEXT,
                source_maps BOOLEAN,
                last_seen TIMESTAMP
            )
        ''')

        # API Intelligence table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_intel (
                id INTEGER PRIMARY KEY,
                target TEXT,
                api_type TEXT,
                url TEXT,
                methods TEXT,
                endpoints TEXT,
                auth_required BOOLEAN,
                last_seen TIMESTAMP
            )
        ''')

        # Cloud resources table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cloud_resources (
                id INTEGER PRIMARY KEY,
                target TEXT,
                resource_type TEXT,
                resource_name TEXT,
                provider TEXT,
                accessible BOOLEAN,
                misconfig_hints TEXT,
                last_seen TIMESTAMP
            )
        ''')

        conn.commit()
        conn.close()

    def add_host(self, target: str, host_data: Dict[str, Any]):
        """Add or update a host."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('''
                INSERT OR REPLACE INTO hosts 
                (target, host, url, ips, status_code, title, tech_stack, exposures, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                target,
                host_data.get('host'),
                host_data.get('url'),
                json.dumps(host_data.get('ips', [])),
                host_data.get('status_code', 0),
                host_data.get('title', 'N/A'),
                json.dumps(host_data.get('tech_hints', [])),
                json.dumps(host_data.get('exposure_hints', [])),
                datetime.now().isoformat()
            ))
            conn.commit()
        except Exception as e:
            print(f"Error adding host: {e}")
        finally:
            conn.close()

    def add_finding(self, target: str, finding_data: Dict[str, Any]):
        """Add a finding with deduplication."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            dedup_hash = hash(f"{finding_data.get('type')}{finding_data.get('affected_asset')}{finding_data.get('description')[:50]}")
            
            cursor.execute('''
                INSERT OR REPLACE INTO findings
                (target, severity, type, description, evidence, affected_asset, score, confidence, 
                 exploitable, deduplication_hash, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                target,
                finding_data.get('severity', 'UNKNOWN'),
                finding_data.get('type', ''),
                finding_data.get('description', ''),
                json.dumps(finding_data.get('evidence', [])),
                finding_data.get('affected_asset', ''),
                finding_data.get('score', 0),
                finding_data.get('confidence', 50),
                finding_data.get('exploitable', False),
                dedup_hash,
                datetime.now().isoformat()
            ))
            conn.commit()
        except Exception as e:
            print(f"Error adding finding: {e}")
        finally:
            conn.close()

    def add_url(self, target: str, url_data: Dict[str, Any]):
        """Add a discovered URL."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('''
                INSERT OR REPLACE INTO urls
                (target, url, method, status_code, has_params, discovered_by, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                target,
                url_data.get('url'),
                url_data.get('method', 'GET'),
                url_data.get('status_code', 0),
                '?' in url_data.get('url', ''),
                url_data.get('discovered_by', 'unknown'),
                datetime.now().isoformat()
            ))
            conn.commit()
        except Exception as e:
            print(f"Error adding URL: {e}")
        finally:
            conn.close()

    def add_secret(self, target: str, secret_data: Dict[str, Any]):
        """Add discovered secret."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            dedup_hash = hash(f"{secret_data.get('secret_type')}{secret_data.get('secret_value')[:30]}")
            
            cursor.execute('''
                INSERT OR REPLACE INTO secrets
                (target, secret_type, secret_value, source_file, source_url, severity, deduplication_hash, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                target,
                secret_data.get('secret_type', 'UNKNOWN'),
                secret_data.get('secret_value', ''),
                secret_data.get('source_file', ''),
                secret_data.get('source_url', ''),
                secret_data.get('severity', 'HIGH'),
                dedup_hash,
                datetime.now().isoformat()
            ))
            conn.commit()
        except Exception as e:
            print(f"Error adding secret: {e}")
        finally:
            conn.close()

    def add_endpoint(self, url: str, endpoint_data: Dict[str, Any]):
        """Add discovered endpoint."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('''
                INSERT INTO endpoints
                (url, path, method, params, api_type, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                url,
                endpoint_data.get('path', ''),
                endpoint_data.get('method', 'GET'),
                json.dumps(endpoint_data.get('params', [])),
                endpoint_data.get('api_type', ''),
                datetime.now().isoformat()
            ))
            conn.commit()
        except Exception as e:
            print(f"Error adding endpoint: {e}")
        finally:
            conn.close()

    def get_findings_by_severity(self, target: str, severity: str) -> List[Dict]:
        """Get findings filtered by severity."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            cursor.execute('''
                SELECT * FROM findings 
                WHERE target = ? AND severity = ?
                ORDER BY score DESC
            ''', (target, severity))
            
            results = [dict(row) for row in cursor.fetchall()]
            return results
        finally:
            conn.close()

    def get_summary(self, target: str) -> Dict[str, Any]:
        """Get scan summary for target."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('SELECT COUNT(*) FROM hosts WHERE target = ?', (target,))
            hosts_count = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM urls WHERE target = ?', (target,))
            urls_count = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM findings WHERE target = ?', (target,))
            findings_count = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM secrets WHERE target = ?', (target,))
            secrets_count = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM subdomains WHERE target = ?', (target,))
            subdomains_count = cursor.fetchone()[0]

            cursor.execute('''
                SELECT severity, COUNT(*) as count FROM findings 
                WHERE target = ? GROUP BY severity
            ''', (target,))
            
            severity_breakdown = {row[0]: row[1] for row in cursor.fetchall()}

            return {
                'hosts': hosts_count,
                'urls': urls_count,
                'findings': findings_count,
                'secrets': secrets_count,
                'subdomains': subdomains_count,
                'findings_by_severity': severity_breakdown
            }
        finally:
            conn.close()

    def export_findings(self, target: str, format: str = 'json') -> str:
        """Export findings in specified format."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            cursor.execute('''
                SELECT * FROM findings WHERE target = ? ORDER BY score DESC
            ''', (target,))
            
            findings = [dict(row) for row in cursor.fetchall()]

            if format == 'json':
                return json.dumps(findings, indent=2, default=str)
            elif format == 'csv':
                if not findings:
                    return ""
                import csv
                import io
                output = io.StringIO()
                writer = csv.DictWriter(output, fieldnames=findings[0].keys())
                writer.writeheader()
                writer.writerows(findings)
                return output.getvalue()
            else:
                return str(findings)
        finally:
            conn.close()
