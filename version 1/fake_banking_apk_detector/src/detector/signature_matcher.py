import json
import logging
from typing import Dict, List, Tuple, Optional
import re
from difflib import SequenceMatcher

class SignatureMatcher:
    """Matches APK signatures against known legitimate and fake patterns"""
    
    def __init__(self, signatures_file: str):
        self.logger = logging.getLogger(__name__)
        self.signatures_file = signatures_file
        self.legitimate_signatures = {}
        self.suspicious_patterns = {}
        
        self._load_signatures()
    
    def _load_signatures(self):
        """Load signature database from JSON file"""
        try:
            with open(self.signatures_file, 'r') as f:
                data = json.load(f)
                
            self.legitimate_signatures = data.get('legitimate_signatures', {})
            self.suspicious_patterns = data.get('suspicious_patterns', {})
            
            self.logger.info(f"Loaded {len(self.legitimate_signatures)} legitimate signatures")
            self.logger.info(f"Loaded {len(self.suspicious_patterns)} suspicious patterns")
            
        except Exception as e:
            self.logger.error(f"Failed to load signatures: {str(e)}")
            self.legitimate_signatures = {}
            self.suspicious_patterns = {}
    
    def match_signatures(self, analysis_result: Dict) -> Dict:
        """
        Match APK against signature database
        
        Args:
            analysis_result: Result from APKAnalyzer
            
        Returns:
            Signature matching results
        """
        try:
            package_name = analysis_result.get('manifest_info', {}).get('package_name', '')
            permissions = analysis_result.get('permissions', [])
            activities = analysis_result.get('activities', [])
            cert_info = analysis_result.get('certificate_info', {})
            
            # Check against legitimate signatures
            legitimate_match = self._check_legitimate_signatures(
                package_name, permissions, activities, cert_info
            )
            
            # Check against suspicious patterns
            suspicious_match = self._check_suspicious_patterns(
                package_name, permissions, activities
            )
            
            # Calculate overall signature score
            signature_score = self._calculate_signature_score(
                legitimate_match, suspicious_match
            )
            
            result = {
                'legitimate_match': legitimate_match,
                'suspicious_match': suspicious_match,
                'signature_score': signature_score,
                'is_known_legitimate': legitimate_match['matched'],
                'is_suspicious_pattern': suspicious_match['matched'],
                'confidence': signature_score['confidence']
            }
            
            return result
            
        except Exception as e:
            self.logger.error(f"Signature matching failed: {str(e)}")
            return self._get_default_result()
    
    def _check_legitimate_signatures(self, package_name: str, permissions: List[str], 
                                   activities: List[str], cert_info: Dict) -> Dict:
        """Check against legitimate bank signatures"""
        best_match = {
            'matched': False,
            'bank': None,
            'confidence': 0.0,
            'matching_criteria': []
        }
        
        for bank, signature in self.legitimate_signatures.items():
            match_score = 0.0
            matching_criteria = []
            
            # Check package name
            legitimate_packages = signature.get('package_names', [])
            if package_name in legitimate_packages:
                match_score += 0.4
                matching_criteria.append('exact_package_match')
            else:
                # Check for similar package names
                for legit_package in legitimate_packages:
                    similarity = SequenceMatcher(None, package_name, legit_package).ratio()
                    if similarity > 0.8:
                        match_score += 0.2 * similarity
                        matching_criteria.append('similar_package_match')
            
            # Check permissions
            expected_permissions = set(signature.get('permissions', []))
            actual_permissions = set(permissions)
            
            if expected_permissions:
                permission_overlap = len(expected_permissions & actual_permissions)
                permission_score = permission_overlap / len(expected_permissions)
                match_score += 0.3 * permission_score
                
                if permission_score > 0.7:
                    matching_criteria.append('permission_match')
            
            # Check activities
            expected_activities = signature.get('activities', [])
            if expected_activities:
                activity_matches = sum(1 for activity in expected_activities 
                                     if activity in activities)
                if activity_matches > 0:
                    activity_score = activity_matches / len(expected_activities)
                    match_score += 0.2 * activity_score
                    matching_criteria.append('activity_match')
            
            # Check certificate (if available)
            expected_certs = signature.get('certificates', [])
            if expected_certs and cert_info:
                # This would require actual certificate comparison
                # For now, we'll skip this check
                pass
            
            # Update best match
            if match_score > best_match['confidence']:
                best_match = {
                    'matched': match_score > 0.5,
                    'bank': bank,
                    'confidence': match_score,
                    'matching_criteria': matching_criteria
                }
        
        return best_match
    
    def _check_suspicious_patterns(self, package_name: str, permissions: List[str], 
                                 activities: List[str]) -> Dict:
        """Check against suspicious patterns"""
        suspicious_indicators = []
        total_score = 0.0
        
        # Check fake package names
        fake_packages = self.suspicious_patterns.get('fake_package_names', [])
        for fake_package in fake_packages:
            if fake_package in package_name:
                suspicious_indicators.append(f'fake_package_pattern: {fake_package}')
                total_score += 0.3
        
        # Check for package name typosquatting
        typo_score = self._check_typosquatting(package_name)
        if typo_score > 0:
            suspicious_indicators.append('possible_typosquatting')
            total_score += typo_score
        
        # Check malicious permissions
        malicious_perms = self.suspicious_patterns.get('malicious_permissions', [])
        malicious_perm_count = sum(1 for perm in permissions if perm in malicious_perms)
        
        if malicious_perm_count > 0:
            perm_score = min(malicious_perm_count * 0.1, 0.4)
            suspicious_indicators.append(f'malicious_permissions: {malicious_perm_count}')
            total_score += perm_score
        
        # Check suspicious activities
        suspicious_activities = self.suspicious_patterns.get('suspicious_activities', [])
        for sus_activity in suspicious_activities:
            if any(sus_activity in activity for activity in activities):
                suspicious_indicators.append(f'suspicious_activity: {sus_activity}')
                total_score += 0.2
        
        # Check for excessive permissions
        if len(permissions) > 20:
            suspicious_indicators.append('excessive_permissions')
            total_score += 0.1
        
        result = {
            'matched': total_score > 0.3,
            'confidence': min(total_score, 1.0),
            'indicators': suspicious_indicators,
            'risk_level': self._get_risk_level(total_score)
        }
        
        return result
    
    def _check_typosquatting(self, package_name: str) -> float:
        """Check for typosquatting against legitimate bank package names"""
        legitimate_packages = []
        
        # Collect all legitimate package names
        for bank_data in self.legitimate_signatures.values():
            legitimate_packages.extend(bank_data.get('package_names', []))
        
        max_similarity = 0.0
        
        for legit_package in legitimate_packages:
            # Skip exact matches (handled elsewhere)
            if package_name == legit_package:
                continue
            
            similarity = SequenceMatcher(None, package_name, legit_package).ratio()
            
            # Check for suspicious similarity (high but not exact)
            if 0.7 <= similarity < 0.95:
                max_similarity = max(max_similarity, similarity)
        
        # Return score based on similarity
        if max_similarity >= 0.8:
            return 0.4  # High typosquatting risk
        elif max_similarity >= 0.7:
            return 0.2  # Medium typosquatting risk
        
        return 0.0
    
    def _calculate_signature_score(self, legitimate_match: Dict, 
                                 suspicious_match: Dict) -> Dict:
        """Calculate overall signature-based score"""
        
        # Start with neutral score
        base_score = 0.5
        
        # Adjust based on legitimate match
        if legitimate_match['matched']:
            # Strong legitimate match reduces fake probability
            legit_adjustment = -0.4 * legitimate_match['confidence']
        else:
            # No legitimate match increases suspicion slightly
            legit_adjustment = 0.1
        
        # Adjust based on suspicious patterns
        if suspicious_match['matched']:
            sus_adjustment = 0.4 * suspicious_match['confidence']
        else:
            sus_adjustment = -0.1
        
        final_score = base_score + legit_adjustment + sus_adjustment
        final_score = max(0.0, min(1.0, final_score))  # Clamp to [0, 1]
        
        # Calculate confidence based on strength of evidence
        confidence = 0.5  # Base confidence
        
        if legitimate_match['matched']:
            confidence += 0.3 * legitimate_match['confidence']
        
        if suspicious_match['matched']:
            confidence += 0.3 * suspicious_match['confidence']
        
        confidence = min(1.0, confidence)
        
        return {
            'fake_probability': final_score,
            'confidence': confidence,
            'reasoning': self._generate_reasoning(legitimate_match, suspicious_match)
        }
    
    def _generate_reasoning(self, legitimate_match: Dict, suspicious_match: Dict) -> str:
        """Generate human-readable reasoning for the signature analysis"""
        reasoning_parts = []
        
        if legitimate_match['matched']:
            bank = legitimate_match['bank']
            criteria = ', '.join(legitimate_match['matching_criteria'])
            reasoning_parts.append(
                f"Matches legitimate {bank} signature ({criteria})"
            )
        else:
            reasoning_parts.append("No match with known legitimate bank signatures")
        
        if suspicious_match['matched']:
            indicators = ', '.join(suspicious_match['indicators'])
            reasoning_parts.append(f"Suspicious patterns detected: {indicators}")
        
        return '; '.join(reasoning_parts)
    
    def _get_risk_level(self, score: float) -> str:
        """Convert score to risk level"""
        if score >= 0.7:
            return 'HIGH'
        elif score >= 0.4:
            return 'MEDIUM'
        elif score >= 0.2:
            return 'LOW'
        else:
            return 'VERY_LOW'
    
    def _get_default_result(self) -> Dict:
        """Return default result when signature matching fails"""
        return {
            'legitimate_match': {'matched': False, 'bank': None, 'confidence': 0.0},
            'suspicious_match': {'matched': False, 'confidence': 0.0, 'indicators': []},
            'signature_score': {'fake_probability': 0.5, 'confidence': 0.0},
            'is_known_legitimate': False,
            'is_suspicious_pattern': False,
            'confidence': 0.0
        }
    
    def add_legitimate_signature(self, bank_name: str, signature_data: Dict):
        """Add new legitimate signature to database"""
        try:
            self.legitimate_signatures[bank_name] = signature_data
            self._save_signatures()
            self.logger.info(f"Added legitimate signature for {bank_name}")
            
        except Exception as e:
            self.logger.error(f"Failed to add legitimate signature: {str(e)}")
    
    def add_suspicious_pattern(self, pattern_type: str, pattern_data: str):
        """Add new suspicious pattern to database"""
        try:
            if pattern_type not in self.suspicious_patterns:
                self.suspicious_patterns[pattern_type] = []
            
            if pattern_data not in self.suspicious_patterns[pattern_type]:
                self.suspicious_patterns[pattern_type].append(pattern_data)
                self._save_signatures()
                self.logger.info(f"Added suspicious pattern: {pattern_type} - {pattern_data}")
            
        except Exception as e:
            self.logger.error(f"Failed to add suspicious pattern: {str(e)}")
    
    def _save_signatures(self):
        """Save signatures back to file"""
        try:
            data = {
                'legitimate_signatures': self.legitimate_signatures,
                'suspicious_patterns': self.suspicious_patterns
            }
            
            with open(self.signatures_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to save signatures: {str(e)}")
