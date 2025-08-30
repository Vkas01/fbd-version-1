import pytest
import numpy as np
from core.feature_extractor import FeatureExtractor

class TestFeatureExtractor:
    
    def test_init(self):
        """Test FeatureExtractor initialization"""
        extractor = FeatureExtractor()
        assert extractor is not None
    
    def test_extract_permission_features(self):
        """Test permission feature extraction"""
        extractor = FeatureExtractor()
        
        apk_info = {
            'permissions': [
                'android.permission.INTERNET',
                'android.permission.READ_CONTACTS',
                'android.permission.SEND_SMS'
            ]
        }
        
        features = extractor.extract_permission_features(apk_info)
        
        assert isinstance(features, list)
        assert len(features) > 0
        assert all(isinstance(f, (int, float)) for f in features)
    
    def test_extract_structural_features(self):
        """Test structural feature extraction"""
        extractor = FeatureExtractor()
        
        apk_info = {
            'activities': ['MainActivity', 'LoginActivity'],
            'services': ['BackgroundService'],
            'receivers': ['BootReceiver'],
            'file_size': 5000000
        }
        
        features = extractor.extract_structural_features(apk_info)
        
        assert isinstance(features, list)
        assert len(features) >= 4  # At least activities, services, receivers, file_size
    
    def test_extract_certificate_features(self):
        """Test certificate feature extraction"""
        extractor = FeatureExtractor()
        
        apk_info = {
            'certificate_info': {
                'issuer': 'CN=Test Bank',
                'subject': 'CN=Banking App',
                'valid': True,
                'self_signed': False
            }
        }
        
        features = extractor.extract_certificate_features(apk_info)
        
        assert isinstance(features, list)
        assert len(features) > 0
    
    def test_extract_features_complete(self):
        """Test complete feature extraction"""
        extractor = FeatureExtractor()
        
        apk_info = {
            'package_name': 'com.test.bank',
            'permissions': ['android.permission.INTERNET'],
            'activities': ['MainActivity'],
            'services': ['BackgroundService'],
            'receivers': [],
            'certificate_info': {
                'issuer': 'CN=Test Bank',
                'valid': True
            },
            'file_size': 1000000
        }
        
        features = extractor.extract_features(apk_info)
        
        assert isinstance(features, list)
        assert len(features) > 0
        assert all(isinstance(f, (int, float)) for f in features)
    
    def test_normalize_features(self):
        """Test feature normalization"""
        extractor = FeatureExtractor()
        
        features = [1, 10, 100, 1000, 0.5]
        normalized = extractor.normalize_features(features)
        
        assert isinstance(normalized, list)
        assert len(normalized) == len(features)
        assert all(0 <= f <= 1 for f in normalized)
