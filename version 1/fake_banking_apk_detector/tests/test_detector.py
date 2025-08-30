import pytest
from unittest.mock import patch, Mock
from core.detector import FakeAPKDetector

class TestFakeAPKDetector:
    
    def test_init(self):
        """Test FakeAPKDetector initialization"""
        detector = FakeAPKDetector()
        assert detector is not None
    
    def test_detect_fake_apk_legitimate(self, detector, sample_apk_path):
        """Test detection of legitimate APK"""
        # Configure mocks for legitimate APK
        detector.ml_classifier.predict.return_value = {
            'is_fake': False,
            'confidence': 0.9,
            'fake_probability': 0.1
        }
        
        with patch.object(detector, '_signature_analysis') as mock_sig:
            mock_sig.return_value = {
                'is_fake': False,
                'confidence': 0.8,
                'fake_probability': 0.2,
                'matched_bank': 'Test Bank'
            }
            
            result = detector.detect_fake_apk(sample_apk_path)
            
            assert result['is_fake'] == False
            assert result['confidence'] > 0.5
            assert result['risk_level'] in ['VERY_LOW', 'LOW']
            assert 'recommendations' in result
            assert 'detection_methods' in result
    
    def test_detect_fake_apk_fake(self, detector, sample_apk_path):
        """Test detection of fake APK"""
        # Configure mocks for fake APK
        detector.ml_classifier.predict.return_value = {
            'is_fake': True,
            'confidence': 0.9,
            'fake_probability': 0.9
        }
        
        with patch.object(detector, '_signature_analysis') as mock_sig:
            mock_sig.return_value = {
                'is_fake': True,
                'confidence': 0.8,
                'fake_probability': 0.8,
                'suspicious_indicators': ['suspicious_permissions']
            }
            
            result = detector.detect_fake_apk(sample_apk_path)
            
            assert result['is_fake'] == True
            assert result['confidence'] > 0.5
            assert result['risk_level'] in ['HIGH', 'CRITICAL']
            assert any('DO NOT INSTALL' in rec for rec in result['recommendations'])
    
    def test_combine_detection_results(self, detector):
        """Test combination of detection results"""
        ml_result = {
            'is_fake': True,
            'confidence': 0.8,
            'fake_probability': 0.8
        }
        
        signature_result = {
            'is_fake': False,
            'confidence': 0.6,
            'fake_probability': 0.4
        }
        
        combined = detector._combine_detection_results(ml_result, signature_result)
        
        assert 'is_fake' in combined
        assert 'confidence' in combined
        assert 'fake_probability' in combined
        assert isinstance(combined['is_fake'], bool)
        assert 0 <= combined['confidence'] <= 1
        assert 0 <= combined['fake_probability'] <= 1
    
    def test_determine_risk_level(self, detector):
        """Test risk level determination"""
        # Test different fake probabilities
        assert detector._determine_risk_level(0.9) == 'CRITICAL'
        assert detector._determine_risk_level(0.7) == 'HIGH'
        assert detector._determine_risk_level(0.5) == 'MEDIUM'
        assert detector._determine_risk_level(0.3) == 'LOW'
        assert detector._determine_risk_level(0.1) == 'VERY_LOW'
    
    def test_generate_recommendations(self, detector):
        """Test recommendation generation"""
        detection_result = {
            'is_fake': True,
            'confidence': 0.9,
            'fake_probability': 0.9,
            'risk_level': 'CRITICAL'
        }
        
        recommendations = detector._generate_recommendations(detection_result)
        
        assert isinstance(recommendations, list)
        assert len(recommendations) > 0
        assert any('DO NOT INSTALL' in rec for rec in recommendations)
    
    def test_batch_detect(self, detector, temp_dir):
        """Test batch detection"""
        # Create multiple test files
        import os
        apk_files = []
        for i in range(3):
            apk_path = os.path.join(temp_dir, f"test_app_{i}.apk")
            with open(apk_path, 'wb') as f:
                f.write(b'PK\x03\x04')
                f.write(b'\x00' * 1000)
            apk_files.append(apk_path)
        
        with patch.object(detector, 'detect_fake_apk') as mock_detect:
            mock_detect.side_effect = [
                {'is_fake': False, 'confidence': 0.8, 'package_name': 'com.legitimate.bank'},
                {'is_fake': True, 'confidence': 0.9, 'package_name': 'com.fake.bank'},
                {'is_fake': False, 'confidence': 0.7, 'package_name': 'com.another.bank'}
            ]
            
            result = detector.batch_detect(temp_dir)
            
            assert result['total_apks'] == 3
            assert result['fake_apks_detected'] == 1
            assert result['legitimate_apks'] == 2
            assert result['fake_percentage'] == 33.33
            assert len(result['results']) == 3
