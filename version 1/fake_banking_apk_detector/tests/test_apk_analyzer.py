import pytest
import os
from unittest.mock import patch, mock_open, Mock
from core.apk_analyzer import APKAnalyzer

class TestAPKAnalyzer:
    
    def test_init(self):
        """Test APKAnalyzer initialization"""
        analyzer = APKAnalyzer()
        assert analyzer is not None
    
    def test_validate_apk_file_valid(self, sample_apk_path):
        """Test APK file validation with valid file"""
        analyzer = APKAnalyzer()
        # Mock the file validation
        with patch('magic.from_file', return_value='Zip archive data'):
            assert analyzer.validate_apk_file(sample_apk_path) == True
    
    def test_validate_apk_file_invalid(self, temp_dir):
        """Test APK file validation with invalid file"""
        analyzer = APKAnalyzer()
        invalid_file = os.path.join(temp_dir, "invalid.txt")
        with open(invalid_file, 'w') as f:
            f.write("not an apk")
        
        with patch('magic.from_file', return_value='ASCII text'):
            assert analyzer.validate_apk_file(invalid_file) == False
    
    def test_validate_apk_file_nonexistent(self):
        """Test APK file validation with non-existent file"""
        analyzer = APKAnalyzer()
        assert analyzer.validate_apk_file("nonexistent.apk") == False
    
    @patch('zipfile.ZipFile')
    def test_extract_manifest_info(self, mock_zipfile, sample_apk_path):
        """Test manifest information extraction"""
        analyzer = APKAnalyzer()
        
        # Mock zipfile behavior
        mock_zip = Mock()
        mock_zipfile.return_value.__enter__.return_value = mock_zip
        mock_zip.namelist.return_value = ['AndroidManifest.xml', 'classes.dex']
        mock_zip.read.return_value = b'mock_manifest_content'
        
        with patch.object(analyzer, '_parse_manifest_xml') as mock_parse:
            mock_parse.return_value = {
                'package_name': 'com.test.app',
                'permissions': ['android.permission.INTERNET'],
                'activities': ['MainActivity']
            }
            
            result = analyzer.extract_manifest_info(sample_apk_path)
            
            assert result['package_name'] == 'com.test.app'
            assert 'android.permission.INTERNET' in result['permissions']
            assert 'MainActivity' in result['activities']
    
    @patch('zipfile.ZipFile')
    def test_extract_certificate_info(self, mock_zipfile, sample_apk_path):
        """Test certificate information extraction"""
        analyzer = APKAnalyzer()
        
        # Mock zipfile behavior
        mock_zip = Mock()
        mock_zipfile.return_value.__enter__.return_value = mock_zip
        mock_zip.namelist.return_value = ['META-INF/CERT.RSA']
        mock_zip.read.return_value = b'mock_cert_content'
        
        with patch('cryptography.x509.load_der_x509_certificate') as mock_load_cert:
            mock_cert = Mock()
            mock_cert.issuer.rfc4514_string.return_value = "CN=Test CA"
            mock_cert.subject.rfc4514_string.return_value = "CN=Test App"
            mock_cert.not_valid_after = Mock()
            mock_cert.not_valid_before = Mock()
            mock_load_cert.return_value = mock_cert
            
            result = analyzer.extract_certificate_info(sample_apk_path)
            
            assert result['issuer'] == "CN=Test CA"
            assert result['subject'] == "CN=Test App"
    
    def test_calculate_file_hash(self, sample_apk_path):
        """Test file hash calculation"""
        analyzer = APKAnalyzer()
        
        hash_result = analyzer.calculate_file_hash(sample_apk_path)
        
        assert 'md5' in hash_result
        assert 'sha1' in hash_result
        assert 'sha256' in hash_result
        assert len(hash_result['md5']) == 32
        assert len(hash_result['sha1']) == 40
        assert len(hash_result['sha256']) == 64
    
    @patch.object(APKAnalyzer, 'extract_manifest_info')
    @patch.object(APKAnalyzer, 'extract_certificate_info')
    @patch.object(APKAnalyzer, 'calculate_file_hash')
    def test_analyze_apk(self, mock_hash, mock_cert, mock_manifest, sample_apk_path):
        """Test complete APK analysis"""
        analyzer = APKAnalyzer()
        
        # Setup mocks
        mock_manifest.return_value = {
            'package_name': 'com.test.bank',
            'permissions': ['android.permission.INTERNET'],
            'activities': ['MainActivity'],
            'services': [],
            'receivers': []
        }
        
        mock_cert.return_value = {
            'issuer': 'Test Bank',
            'subject': 'Banking App',
            'valid': True
        }
        
        mock_hash.return_value = {
            'md5': 'test_md5_hash',
            'sha1': 'test_sha1_hash',
            'sha256': 'test_sha256_hash'
        }
        
        result = analyzer.analyze_apk(sample_apk_path)
        
        assert result['package_name'] == 'com.test.bank'
        assert result['permissions'] == ['android.permission.INTERNET']
        assert result['certificate_info']['issuer'] == 'Test Bank'
        assert result['file_hashes']['md5'] == 'test_md5_hash'
        assert result['file_size'] > 0
