import os
import zipfile
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple
import hashlib
import subprocess
import tempfile
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import logging

class APKAnalyzer:
    """Analyzes APK files to extract metadata and features"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    def analyze_apk(self, apk_path: str) -> Dict:
        """
        Comprehensive APK analysis
        
        Args:
            apk_path: Path to the APK file
            
        Returns:
            Dictionary containing analysis results
        """
        try:
            analysis_result = {
                'file_info': self._get_file_info(apk_path),
                'manifest_info': self._analyze_manifest(apk_path),
                'certificate_info': self._analyze_certificate(apk_path),
                'permissions': self._extract_permissions(apk_path),
                'activities': self._extract_activities(apk_path),
                'services': self._extract_services(apk_path),
                'receivers': self._extract_receivers(apk_path),
                'file_structure': self._analyze_file_structure(apk_path),
                'strings': self._extract_strings(apk_path),
                'native_libraries': self._extract_native_libraries(apk_path)
            }
            
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"Error analyzing APK {apk_path}: {str(e)}")
            raise
    
    def _get_file_info(self, apk_path: str) -> Dict:
        """Extract basic file information"""
        stat = os.stat(apk_path)
        
        with open(apk_path, 'rb') as f:
            content = f.read()
            md5_hash = hashlib.md5(content).hexdigest()
            sha256_hash = hashlib.sha256(content).hexdigest()
        
        return {
            'size': stat.st_size,
            'md5': md5_hash,
            'sha256': sha256_hash,
            'path': apk_path
        }
    
    def _analyze_manifest(self, apk_path: str) -> Dict:
        """Analyze AndroidManifest.xml"""
        try:
            # Use aapt to dump manifest
            result = subprocess.run([
                'aapt', 'dump', 'xmltree', apk_path, 'AndroidManifest.xml'
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                self.logger.warning(f"aapt failed for {apk_path}")
                return self._fallback_manifest_analysis(apk_path)
            
            return self._parse_aapt_output(result.stdout)
            
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return self._fallback_manifest_analysis(apk_path)
    
    def _fallback_manifest_analysis(self, apk_path: str) -> Dict:
        """Fallback manifest analysis using zipfile"""
        try:
            with zipfile.ZipFile(apk_path, 'r') as zip_file:
                if 'AndroidManifest.xml' in zip_file.namelist():
                    manifest_data = zip_file.read('AndroidManifest.xml')
                    # Basic analysis of binary XML
                    return {
                        'package_name': self._extract_package_name_binary(manifest_data),
                        'version_code': None,
                        'version_name': None,
                        'min_sdk_version': None,
                        'target_sdk_version': None
                    }
        except Exception as e:
            self.logger.error(f"Fallback manifest analysis failed: {str(e)}")
        
        return {}
    
    def _parse_aapt_output(self, aapt_output: str) -> Dict:
        """Parse aapt dump output"""
        manifest_info = {}
        
        lines = aapt_output.split('\n')
        for line in lines:
            if 'package=' in line:
                package_match = line.split('package=')[1].split()[0].strip('"')
                manifest_info['package_name'] = package_match
            elif 'versionCode=' in line:
                version_code = line.split('versionCode=')[1].split()[0].strip('"')
                manifest_info['version_code'] = version_code
            elif 'versionName=' in line:
                version_name = line.split('versionName=')[1].split()[0].strip('"')
                manifest_info['version_name'] = version_name
        
        return manifest_info
    
    def _analyze_certificate(self, apk_path: str) -> Dict:
        """Analyze APK certificate"""
        try:
            # Extract certificate using jarsigner or apksigner
            with tempfile.TemporaryDirectory() as temp_dir:
                cert_path = os.path.join(temp_dir, 'cert.pem')
                
                # Try to extract certificate
                result = subprocess.run([
                    'keytool', '-printcert', '-jarfile', apk_path
                ], capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    return self._parse_certificate_info(result.stdout)
                
        except Exception as e:
            self.logger.error(f"Certificate analysis failed: {str(e)}")
        
        return {}
    
    def _parse_certificate_info(self, cert_output: str) -> Dict:
        """Parse certificate information"""
        cert_info = {}
        
        lines = cert_output.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('Owner:'):
                cert_info['owner'] = line.replace('Owner:', '').strip()
            elif line.startswith('Issuer:'):
                cert_info['issuer'] = line.replace('Issuer:', '').strip()
            elif line.startswith('Serial number:'):
                cert_info['serial'] = line.replace('Serial number:', '').strip()
        
        return cert_info
    
    def _extract_permissions(self, apk_path: str) -> List[str]:
        """Extract permissions from APK"""
        try:
            result = subprocess.run([
                'aapt', 'dump', 'permissions', apk_path
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                permissions = []
                for line in result.stdout.split('\n'):
                    if line.startswith('uses-permission:'):
                        perm = line.split("'")[1] if "'" in line else ""
                        if perm:
                            permissions.append(perm)
                return permissions
                
        except Exception as e:
            self.logger.error(f"Permission extraction failed: {str(e)}")
        
        return []
    
    def _extract_activities(self, apk_path: str) -> List[str]:
        """Extract activities from APK"""
        try:
            result = subprocess.run([
                'aapt', 'dump', 'xmltree', apk_path, 'AndroidManifest.xml'
            ], capture_output=True, text=True, timeout=30)
            
            activities = []
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'activity' in line.lower() and 'name=' in line:
                        # Extract activity name
                        parts = line.split('name=')
                        if len(parts) > 1:
                            activity_name = parts[1].split()[0].strip('"')
                            activities.append(activity_name)
            
            return activities
            
        except Exception as e:
            self.logger.error(f"Activity extraction failed: {str(e)}")
        
        return []
    
    def _extract_services(self, apk_path: str) -> List[str]:
        """Extract services from APK"""
        # Similar implementation to activities
        return []
    
    def _extract_receivers(self, apk_path: str) -> List[str]:
        """Extract broadcast receivers from APK"""
        # Similar implementation to activities
        return []
    
    def _analyze_file_structure(self, apk_path: str) -> Dict:
        """Analyze APK file structure"""
        try:
            with zipfile.ZipFile(apk_path, 'r') as zip_file:
                files = zip_file.namelist()
                
                structure = {
                    'total_files': len(files),
                    'has_classes_dex': 'classes.dex' in files,
                    'has_resources': 'resources.arsc' in files,
                    'has_manifest': 'AndroidManifest.xml' in files,
                    'native_libs': [f for f in files if f.startswith('lib/')],
                    'assets': [f for f in files if f.startswith('assets/')],
                    'res_files': [f for f in files if f.startswith('res/')]
                }
                
                return structure
                
        except Exception as e:
            self.logger.error(f"File structure analysis failed: {str(e)}")
        
        return {}
    
    def _extract_strings(self, apk_path: str) -> List[str]:
        """Extract strings from APK"""
        try:
            result = subprocess.run([
                'strings', apk_path
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                strings = result.stdout.split('\n')
                # Filter relevant strings
                relevant_strings = []
                for s in strings:
                    s = s.strip()
                    if len(s) > 5 and any(keyword in s.lower() for keyword in 
                                        ['bank', 'login', 'password', 'otp', 'account']):
                        relevant_strings.append(s)
                
                return relevant_strings[:100]  # Limit to first 100
                
        except Exception as e:
            self.logger.error(f"String extraction failed: {str(e)}")
        
        return []
    
    def _extract_native_libraries(self, apk_path: str) -> List[str]:
        """Extract native library information"""
        try:
            with zipfile.ZipFile(apk_path, 'r') as zip_file:
                lib_files = [f for f in zip_file.namelist() if f.startswith('lib/')]
                
                libraries = []
                for lib_file in lib_files:
                    if lib_file.endswith('.so'):
                        libraries.append(lib_file)
                
                return libraries
                
        except Exception as e:
            self.logger.error(f"Native library extraction failed: {str(e)}")
        
        return []
    
    def _extract_package_name_binary(self, manifest_data: bytes) -> Optional[str]:
        """Extract package name from binary AndroidManifest.xml"""
        # This is a simplified implementation
        # In practice, you'd need a proper binary XML parser
        try:
            manifest_str = manifest_data.decode('utf-8', errors='ignore')
            # Look for package name patterns
            import re
            package_pattern = r'([a-zA-Z][a-zA-Z0-9_]*\.)+[a-zA-Z][a-zA-Z0-9_]*'
            matches = re.findall(package_pattern, manifest_str)
            
            # Filter for likely package names
            for match in matches:
                if '.' in match and len(match.split('.')) >= 2:
                    return match
                    
        except Exception:
            pass
        
        return None
