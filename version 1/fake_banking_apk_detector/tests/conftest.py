import pytest
import tempfile
import os
import shutil
from unittest.mock import Mock, patch
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.detector import FakeAPKDetector
from core.apk_analyzer import APKAnalyzer
from core.feature_extractor import FeatureExtractor
from models.ml_classifier import MLClassifier
from utils.file_handler import FileHandler

@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests"""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)

@pytest.fixture
def sample_apk_path(temp_dir):
    """Create a mock APK file for testing"""
    apk_path = os.path.join(temp_dir, "test_app.apk")
    # Create a dummy APK file (in real tests, you'd use actual APK files)
    with open(apk_path, 'wb') as f:
        f.write(b'PK\x03\x04')  # ZIP file signature
        f.write(b'\x00' * 1000)  # Dummy content
    return apk_path

@pytest.fixture
def mock_apk_analyzer():
    """Mock APK analyzer for testing"""
    analyzer = Mock(spec=APKAnalyzer)
    analyzer.analyze_apk.return_value = {
        'package_name': 'com.test.bank',
        'permissions': ['android.permission.INTERNET'],
        'activities': ['MainActivity'],
        'services': [],
        'receivers': [],
        'certificate_info': {'issuer': 'Test Bank', 'valid': True},
        'file_size': 1024,
        'md5_hash': 'test_hash'
    }
    return analyzer

@pytest.fixture
def mock_feature_extractor():
    """Mock feature extractor for testing"""
    extractor = Mock(spec=FeatureExtractor)
    extractor.extract_features.return_value = [0.5] * 50  # 50 dummy features
    return extractor

@pytest.fixture
def mock_ml_classifier():
    """Mock ML classifier for testing"""
    classifier = Mock(spec=MLClassifier)
    classifier.is_trained = True
    classifier.predict.return_value = {
        'is_fake': False,
        'confidence': 0.8,
        'fake_probability': 0.2
    }
    return classifier

@pytest.fixture
def detector(mock_apk_analyzer, mock_feature_extractor, mock_ml_classifier):
    """Create a detector instance with mocked components"""
    detector = FakeAPKDetector()
    detector.apk_analyzer = mock_apk_analyzer
    detector.feature_extractor = mock_feature_extractor
    detector.ml_classifier = mock_ml_classifier
    return detector

@pytest.fixture
def flask_app():
    """Create Flask app for testing"""
    from api.flask_app import app
    app.config['TESTING'] = True
    app.config['UPLOAD_FOLDER'] = tempfile.mkdtemp()
    return app
