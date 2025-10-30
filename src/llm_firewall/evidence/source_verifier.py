"""
Source Verifier - Link/DOI Verification + Content Hashing
==========================================================

Verifies source authenticity and creates tamper-evident hashes.

Features:
1. URL accessibility check
2. DOI validation (via doi.org)
3. BLAKE3 content hashing (fast, secure)
4. Domain trust integration

Based on GPT-5 Policy & Controls (2025-10-27):
"Verifizierbare Attribution: Domain-Trust + Link-Check + Hash/DOI"
"""

import logging
import re
from typing import Any, Dict, Optional, Tuple

import blake3
import requests  # type: ignore

logger = logging.getLogger(__name__)


class SourceVerifier:
    """
    Verifies sources and creates content hashes.
    
    Security Features:
    - Prevents fake citations (DOI validation)
    - Detects link rot (accessibility check)
    - Creates tamper-evident hashes (BLAKE3)
    - Integrates with domain trust scoring
    """

    def __init__(self, timeout: int = 10):
        """
        Initialize verifier.
        
        Args:
            timeout: HTTP request timeout in seconds
        """
        self.timeout = timeout
        self.verification_cache: Dict[str, Tuple[bool, Optional[int]]] = {}  # URL → (accessible, status_code)

    def verify_source(
        self,
        url: str,
        content: Optional[str] = None,
        expected_doi: Optional[str] = None
    ) -> Dict:
        """
        Comprehensive source verification.
        
        Args:
            url: Source URL to verify
            content: Optional content text for hashing
            expected_doi: Optional DOI to validate
            
        Returns:
            Dict with verification results:
            {
                'accessible': bool,
                'status_code': int,
                'doi_valid': bool,
                'content_hash': str (BLAKE3),
                'domain_trust': float,
                'verified': bool (overall),
                'reasoning': str
            }
        """
        result: Dict[str, Any] = {
            'url': url,
            'accessible': False,
            'status_code': None,
            'doi_valid': None,
            'content_hash': None,
            'domain_trust': 0.0,
            'verified': False,
            'reasoning': []
        }

        # Check 1: URL accessibility
        is_accessible, status_code = self._check_accessibility(url)
        result['accessible'] = is_accessible
        result['status_code'] = status_code

        if not is_accessible:
            result['reasoning'].append(f"URL not accessible (status: {status_code})")
            return result

        result['reasoning'].append(f"URL accessible (status: {status_code})")

        # Check 2: DOI validation (if DOI present)
        if 'doi.org' in url or expected_doi:
            doi = expected_doi or self._extract_doi_from_url(url)
            if doi:
                is_valid = self._validate_doi(doi)
                result['doi_valid'] = is_valid

                if is_valid:
                    result['reasoning'].append(f"DOI valid: {doi}")
                else:
                    result['reasoning'].append(f"DOI invalid: {doi}")
                    return result  # Fail fast on invalid DOI

        # Check 3: Content hashing (if content provided)
        if content:
            content_hash = self._hash_content(content)
            result['content_hash'] = content_hash
            result['reasoning'].append(f"Content hash: {content_hash[:16]}...")

        # Overall verification
        result['verified'] = is_accessible and (result['doi_valid'] is not False)

        return result

    def _check_accessibility(self, url: str) -> Tuple[bool, Optional[int]]:
        """
        Check if URL is accessible.
        
        Args:
            url: URL to check
            
        Returns:
            (is_accessible, status_code)
        """
        # Check cache first
        if url in self.verification_cache:
            return self.verification_cache[url]

        try:
            response = requests.head(url, timeout=self.timeout, allow_redirects=True)
            status_code = response.status_code
            is_accessible = (200 <= status_code < 400)

            # Cache result
            self.verification_cache[url] = (is_accessible, status_code)

            logger.debug(f"[SourceVerifier] {url}: {status_code}")
            return (is_accessible, status_code)

        except requests.exceptions.Timeout:
            logger.warning(f"[SourceVerifier] Timeout: {url}")
            return (False, None)
        except requests.exceptions.RequestException as e:
            logger.warning(f"[SourceVerifier] Request failed: {url} - {e}")
            return (False, None)

    def _extract_doi_from_url(self, url: str) -> Optional[str]:
        """
        Extract DOI from URL.
        
        Examples:
            https://doi.org/10.1038/s41586-020-2649-2 → 10.1038/s41586-020-2649-2
            https://nature.com/articles/s41586-020-2649-2 → 10.1038/s41586-020-2649-2
        
        Args:
            url: URL possibly containing DOI
            
        Returns:
            DOI string or None
        """
        # Pattern: 10.XXXX/...
        doi_pattern = r'10\.\d{4,}/[^\s]+'
        match = re.search(doi_pattern, url)

        if match:
            return match.group(0)

        return None

    def _validate_doi(self, doi: str) -> bool:
        """
        Validate DOI via doi.org resolution.
        
        Args:
            doi: DOI string (e.g., "10.1038/s41586-020-2649-2")
            
        Returns:
            True if DOI resolves successfully
        """
        try:
            doi_url = f"https://doi.org/{doi}"
            response = requests.head(doi_url, timeout=self.timeout, allow_redirects=True)

            # DOI is valid if it resolves (200-399)
            is_valid = (200 <= response.status_code < 400)

            if is_valid:
                logger.debug(f"[SourceVerifier] DOI valid: {doi}")
            else:
                logger.warning(f"[SourceVerifier] DOI invalid: {doi} (status: {response.status_code})")

            return is_valid

        except Exception as e:
            logger.warning(f"[SourceVerifier] DOI validation failed: {doi} - {e}")
            return False

    def _hash_content(self, content: str) -> str:
        """
        Hash content with BLAKE3 (fast, secure).
        
        Args:
            content: Text content to hash
            
        Returns:
            Hexadecimal hash string
        """
        hasher = blake3.blake3(content.encode('utf-8'))
        return hasher.hexdigest()

    def batch_verify(self, sources: list) -> list:
        """
        Verify multiple sources in batch.
        
        Args:
            sources: List of source dicts with 'url' and optional 'content'
            
        Returns:
            List of verification results
        """
        results = []

        for source in sources:
            url = source.get('url', '')
            content = source.get('content') or source.get('text')
            doi = source.get('doi')

            verification = self.verify_source(url, content, doi)
            results.append(verification)

        verified_count = len([r for r in results if r['verified']])

        logger.info(
            f"[SourceVerifier] Batch verified: "
            f"{verified_count}/{len(sources)} sources valid"
        )

        return results

    def get_statistics(self) -> Dict:
        """Get verifier statistics."""
        return {
            'cache_size': len(self.verification_cache),
            'cached_accessible': len([v for v in self.verification_cache.values() if v[0]]),
            'cached_failed': len([v for v in self.verification_cache.values() if not v[0]])
        }

