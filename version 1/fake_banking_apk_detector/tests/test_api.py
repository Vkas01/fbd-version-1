import pytest
import json
import io
from unittest.mock import patch, Mock

class TestAPI:
    
    def test_health_check(self, flask_app):
        """Test health check endpoint"""
        with flask_app.test_client() as client:
            response = client.get('/api/health')
            
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['status'] == 'healthy'
    
    def test_stats_endpoint(self, flask_app):
        """Test statistics endpoint"""
        with flask_app.test_client() as client:
            response = client.get('/api/stats')
            
            assert response.status_code == 200
            data = json.loads(response.data)
            assert 'total_detections' in data
            assert 'fake_apks_detected' in data
    
    @patch('core.detector.FakeAPKDetector')
    def test_detect_endpoint_success(self, mock_detector_class, flask_app):
        """Test successful APK detection"""
        # Mock detector
        mock_detector = Mock()
        mock_detector.detect_fake_apk.return_value = {
            'package_name': 'com.test.bank',
            'is_fake': False,
            'confidence': 0.8,
            'risk_level': 'LOW',
            'fake_probability': 0.2,
            'recommendations': ['App appears legitimate'],
            'detection_methods': {},
            'apk_details': {}
        }
        mock_detector_class.return_value = mock_detector
        
        with flask_app.test_client() as client:
            # Create fake APK file
            data = {
                'apk_file': (io.BytesIO(b'PK\x03\x04' + b'\x00' * 1000), 'test.apk')
            }
            
            response = client.post('/api/detect', 
                                 data=data,
                                 content_type='multipart/form-data')
            
            assert response.status_code == 200
            result = json.loads(response.data)
            assert result['success'] == True
            assert result['result']['is_fake'] == False
    
    def test_detect_endpoint_no_file(self, flask_app):
        """Test detection endpoint without file"""
        with flask_app.test_client() as client:
            response = client.post('/api/detect')
            
            assert response.status_code == 400
            data = json.loads(response.data)
            assert 'error' in data
    
    def test_detect_endpoint_invalid_file(self, flask_app):
        """Test detection endpoint with invalid file"""
        with flask_app.test_client() as client:
            data = {
                'apk_file': (io.BytesIO(b'not an apk'), 'test.txt')
            }
            
            response = client.post('/api/detect',
                                 data=data,
                                 content_type='multipart/form-data')
            
            assert response.status_code == 400
            result = json.loads(response.data)
            assert 'error' in result
    
    @patch('core.detector.FakeAPKDetector')
    def test_batch_detect_endpoint(self, mock_detector_class, flask_app):
        """Test batch detection endpoint"""
        # Mock detector
        mock_detector = Mock()
        mock_detector.batch_detect.return_value = {
            'total_apks': 2,
            'fake_apks_detected': 1,
            'legitimate_apks': 1,
            'fake_percentage': 50.0,
            'summary': {},
            'results': [
                {'is_fake': False, 'confidence': 0.8},
                {'is_fake': True, 'confidence': 0.9}
            ]
        }
        mock_detector_class.return_value = mock_detector
        
        with flask_app.test_client() as client:
            data = {
                'apk_files': [
                    (io.BytesIO(b'PK\x03\x04' + b'\x00' * 1000), 'test1.apk'),
                    (io.BytesIO(b'PK\x03\x04' + b'\x00' * 1000), 'test2.apk')
                ]
            }
            
            response = client.post('/api/batch-detect',
                                 data=data,
                                 content_type='multipart/form-data')
            
            assert response.status_code == 200
            result = json.loads(response.data)
            assert result['success'] == True
            assert result['result']['total_apks'] == 2
