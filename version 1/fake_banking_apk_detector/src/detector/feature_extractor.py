import numpy as np
from typing import Dict, List, Any
import re
import logging
from collections import Counter

class FeatureExtractor:
    """Extracts features from APK analysis results for ML classification"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Suspicious permission patterns
        self.suspicious_permissions = [
            'android.permission.SEND_SMS',
            'android.permission.READ_SMS',
            'android.permission.RECEIVE_SMS',
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.RECORD_AUDIO',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.CALL_PHONE',
            'android.permission.READ_PHONE_STATE',
            'android.permission.PROCESS_OUTGOING_CALLS',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.SYSTEM_ALERT_WINDOW',
            'android.permission.DEVICE_ADMIN'
        ]
        
        # Banking-related keywords
        self.banking_keywords = [
            'bank', 'banking', 'account', 'balance', 'transaction',
            'transfer', 'payment', 'otp', 'pin', 'password', 'login',
            'netbanking', 'mobile banking', 'upi', 'wallet', 'credit',
            'debit', 'card', 'atm', 'neft', 'rtgs', 'imps'
        ]
        
        # Indian bank names
        self.indian_banks = [
            'sbi', 'hdfc', 'icici', 'axis', 'kotak', 'pnb', 'bob',
            'canara', 'union', 'indian', 'idfc', 'yes', 'indusind',
            'federal', 'south indian', 'karur vysya', 'city union',
            'dhanlaxmi', 'jammu kashmir', 'punjab sind'
        ]
    
    def extract_features(self, analysis_result: Dict) -> np.ndarray:
        """
        Extract feature vector from APK analysis result
        
        Args:
            analysis_result: Result from APKAnalyzer
            
        Returns:
            Feature vector as numpy array
        """
        try:
            features = []
            
            # File-based features
            features.extend(self._extract_file_features(analysis_result.get('file_info', {})))
            
            # Manifest-based features
            features.extend(self._extract_manifest_features(analysis_result.get('manifest_info', {})))
            
            # Permission-based features
            features.extend(self._extract_permission_features(analysis_result.get('permissions', [])))
            
            # Activity-based features
            features.extend(self._extract_activity_features(analysis_result.get('activities', [])))
            
            # Certificate-based features
            features.extend(self._extract_certificate_features(analysis_result.get('certificate_info', {})))
            
            # String-based features
            features.extend(self._extract_string_features(analysis_result.get('strings', [])))
            
            # Structure-based features
            features.extend(self._extract_structure_features(analysis_result.get('file_structure', {})))
            
            # Native library features
            features.extend(self._extract_native_lib_features(analysis_result.get('native_libraries', [])))
            
            return np.array(features, dtype=np.float32)
            
        except Exception as e:
            self.logger.error(f"Feature extraction failed: {str(e)}")
            # Return zero vector if extraction fails
            return np.zeros(self.get_feature_count(), dtype=np.float32)
    
    def _extract_file_features(self, file_info: Dict) -> List[float]:
        """Extract features from file information"""
        features = []
        
        # File size (normalized)
        size = file_info.get('size', 0)
        features.append(min(size / (50 * 1024 * 1024), 1.0))  # Normalize by 50MB
        
        return features
    
    def _extract_manifest_features(self, manifest_info: Dict) -> List[float]:
        """Extract features from manifest information"""
        features = []
        
        package_name = manifest_info.get('package_name', '')
        
        # Package name analysis
        features.append(float(self._is_suspicious_package_name(package_name)))
        features.append(float(self._contains_bank_name(package_name)))
        features.append(float(len(package_name.split('.')) if package_name else 0) / 10.0)
        
        # Version information
        version_code = manifest_info.get('version_code')
        features.append(float(version_code is not None))
        
        version_name = manifest_info.get('version_name', '')
        features.append(float(bool(version_name)))
        
        return features
    
    def _extract_permission_features(self, permissions: List[str]) -> List[float]:
        """Extract features from permissions"""
        features = []
        
        # Total number of permissions (normalized)
        features.append(min(len(permissions) / 50.0, 1.0))
        
        # Suspicious permissions count
        suspicious_count = sum(1 for perm in permissions if perm in self.suspicious_permissions)
        features.append(min(suspicious_count / 10.0, 1.0))
        
        # Specific permission checks
        for sus_perm in self.suspicious_permissions[:10]:  # Top 10 suspicious permissions
            features.append(float(sus_perm in permissions))
        
        # Internet permission (expected for banking apps)
        features.append(float('android.permission.INTERNET' in permissions))
        
        # Camera permission (common in legitimate banking apps)
        features.append(float('android.permission.CAMERA' in permissions))
        
        return features
    
    def _extract_activity_features(self, activities: List[str]) -> List[float]:
        """Extract features from activities"""
        features = []
        
        # Number of activities (normalized)
        features.append(min(len(activities) / 20.0, 1.0))
        
        # Suspicious activity patterns
        suspicious_patterns = ['fake', 'phish', 'malware', 'trojan', 'virus']
        suspicious_activity_count = 0
        
        for activity in activities:
            activity_lower = activity.lower()
            if any(pattern in activity_lower for pattern in suspicious_patterns):
                suspicious_activity_count += 1
        
        features.append(min(suspicious_activity_count / 5.0, 1.0))
        
        # Banking-related activities
        banking_activity_count = 0
        for activity in activities:
            activity_lower = activity.lower()
            if any(keyword in activity_lower for keyword in self.banking_keywords):
                banking_activity_count += 1
        
        features.append(min(banking_activity_count / 10.0, 1.0))
        
        return features
    
    def _extract_certificate_features(self, cert_info: Dict) -> List[float]:
        """Extract features from certificate information"""
        features = []
        
        # Certificate presence
        features.append(float(bool(cert_info)))
        
        # Owner information analysis
        owner = cert_info.get('owner', '')
        features.append(float(self._contains_bank_name(owner)))
        features.append(float('CN=' in owner))  # Proper certificate format
        
        # Issuer information
        issuer = cert_info.get('issuer', '')
        features.append(float(issuer == owner))  # Self-signed certificate
        
        return features
    
    def _extract_string_features(self, strings: List[str]) -> List[float]:
        """Extract features from strings"""
        features = []
        
        # Banking keyword frequency
        banking_keyword_count = 0
        suspicious_keyword_count = 0
        
        suspicious_keywords = ['fake', 'phish', 'steal', 'hack', 'crack', 'bypass']
        
        for string in strings:
            string_lower = string.lower()
            
            # Count banking keywords
            banking_keyword_count += sum(1 for keyword in self.banking_keywords 
                                       if keyword in string_lower)
            
            # Count suspicious keywords
            suspicious_keyword_count += sum(1 for keyword in suspicious_keywords 
                                          if keyword in string_lower)
        
        features.append(min(banking_keyword_count / 50.0, 1.0))
        features.append(min(suspicious_keyword_count / 10.0, 1.0))
        
        # URL analysis
        url_count = sum(1 for s in strings if 'http' in s.lower())
        features.append(min(url_count / 20.0, 1.0))
        
        return features
    
    def _extract_structure_features(self, structure: Dict) -> List[float]:
        """Extract features from file structure"""
        features = []
        
        # Basic structure checks
        features.append(float(structure.get('has_classes_dex', False)))
        features.append(float(structure.get('has_resources', False)))
        features.append(float(structure.get('has_manifest', False)))
        
        # File counts (normalized)
        total_files = structure.get('total_files', 0)
        features.append(min(total_files / 1000.0, 1.0))
        
        # Native libraries
        native_libs = structure.get('native_libs', [])
        features.append(min(len(native_libs) / 10.0, 1.0))
        
        # Assets and resources
        assets = structure.get('assets', [])
        res_files = structure.get('res_files', [])
        features.append(min(len(assets) / 50.0, 1.0))
        features.append(min(len(res_files) / 200.0, 1.0))
        
        return features
    
    def _extract_native_lib_features(self, native_libs: List[str]) -> List[float]:
        """Extract features from native libraries"""
        features = []
        
        # Number of native libraries
        features.append(min(len(native_libs) / 10.0, 1.0))
        
        # Architecture analysis
        architectures = set()
        for lib in native_libs:
            if '/arm64-v8a/' in lib:
                architectures.add('arm64')
            elif '/armeabi-v7a/' in lib:
                architectures.add('arm32')
            elif '/x86/' in lib:
                architectures.add('x86')
            elif '/x86_64/' in lib:
                architectures.add('x86_64')
        
        features.append(float(len(architectures)))
        
        return features
    
    def _is_suspicious_package_name(self, package_name: str) -> bool:
        """Check if package name is suspicious"""
        if not package_name:
            return True
        
        suspicious_patterns = [
            r'com\.fake\.',
            r'com\.test\.',
            r'com\.example\.',
            r'\.fake\.',
            r'\.phish\.',
            r'\.malware\.'
        ]
        
        package_lower = package_name.lower()
        
        for pattern in suspicious_patterns:
            if re.search(pattern, package_lower):
                return True
        
        # Check for common typos of legitimate banks
        typo_patterns = [
            'hdfc.*bank', 'sbi.*bank', 'icici.*bank', 'axis.*bank'
        ]
        
        for pattern in typo_patterns:
            if re.search(pattern, package_lower) and 'com.hdfc' not in package_lower:
                return True
        
        return False
    
    def _contains_bank_name(self, text: str) -> bool:
        """Check if text contains Indian bank names"""
        if not text:
            return False
        
        text_lower = text.lower()
        return any(bank in text_lower for bank in self.indian_banks)
    
    def get_feature_count(self) -> int:
        """Get total number of features"""
        # Calculate based on feature extraction methods
        return (1 +  # file features
                5 +  # manifest features  
                13 + # permission features (3 + 10 specific permissions)
                3 +  # activity features
                4 +  # certificate features
                3 +  # string features
                7 +  # structure features
                2)   # native lib features
    
    def get_feature_names(self) -> List[str]:
        """Get feature names for interpretability"""
        names = []
        
        # File features
        names.append('file_size_normalized')
        
        # Manifest features
        names.extend([
            'suspicious_package_name',
            'contains_bank_name',
            'package_depth',
            'has_version_code',
            'has_version_name'
        ])
        
        # Permission features
        names.extend([
            'total_permissions',
            'suspicious_permissions_count',
        ])
        
        # Add specific suspicious permissions
        for perm in self.suspicious_permissions[:10]:
            names.append(f'has_{perm.split(".")[-1].lower()}')
        
        names.extend(['has_internet', 'has_camera'])
        
        # Activity features
        names.extend([
            'activity_count',
            'suspicious_activities',
            'banking_activities'
        ])
        
        # Certificate features
        names.extend([
            'has_certificate',
            'cert_owner_has_bank',
            'cert_proper_format',
            'self_signed_cert'
        ])
        
        # String features
        names.extend([
            'banking_keywords_count',
            'suspicious_keywords_count',
            'url_count'
        ])
        
        # Structure features
        names.extend([
            'has_classes_dex',
            'has_resources',
            'has_manifest',
            'total_files_count',
            'native_libs_count',
            'assets_count',
            'res_files_count'
        ])
        
        # Native lib features
        names.extend([
            'native_lib_count',
            'architecture_count'
        ])
        
        return names
