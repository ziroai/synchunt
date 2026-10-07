import os
import json
from core.utils import read_file_lines, write_file_lines, save_json, is_in_scope


class ScopeManager:
    """Manage target scope: in-scope domains, out-of-scope filtering, target relationships."""

    def __init__(self, config, logger, output_dir, target, scope_file=None, out_of_scope_file=None):
        self.config = config
        self.logger = logger
        self.output_dir = os.path.join(output_dir, 'scope')
        self.target = target
        self.scope_file = scope_file or config.get('general.scope_file', '')
        self.out_of_scope_file = out_of_scope_file or config.get('general.out_of_scope_file', '')
        
        self.in_scope = self._load_scope(self.scope_file) if self.scope_file else [target]
        self.out_of_scope = self._load_scope(self.out_of_scope_file) if self.out_of_scope_file else []
        
        os.makedirs(self.output_dir, exist_ok=True)

    def _load_scope(self, filepath):
        """Load scope list from file."""
        if filepath and os.path.exists(filepath):
            return read_file_lines(filepath)
        return []

    def is_in_scope(self, domain):
        """Check if domain is in scope."""
        if self.out_of_scope and is_in_scope(domain, self.out_of_scope):
            return False
        if self.in_scope:
            return is_in_scope(domain, self.in_scope)
        return True

    def filter_domains(self, domains):
        """Filter domains by scope."""
        return [d for d in domains if self.is_in_scope(d)]

    def generate_scope_report(self):
        """Generate scope report."""
        report = {
            'target': self.target,
            'in_scope': self.in_scope,
            'out_of_scope': self.out_of_scope,
            'count_in_scope': len(self.in_scope),
            'count_out_of_scope': len(self.out_of_scope)
        }
        
        output_file = os.path.join(self.output_dir, 'scope_report.json')
        save_json(report, output_file)
        
        summary = [
            f"In Scope: {len(self.in_scope)} domains",
            f"Out of Scope: {len(self.out_of_scope)} domains",
            "",
            "In Scope Domains:"
        ] + self.in_scope + [
            "",
            "Out of Scope Domains:"
        ] + self.out_of_scope
        
        write_file_lines(os.path.join(self.output_dir, 'scope_summary.txt'), summary)
        return output_file
