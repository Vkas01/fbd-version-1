import pytest
import numpy as np
from unittest.mock import patch, Mock
from models.ml_classifier import MLClassifier

class TestMLClassifier:
    
    def test_init(self):
        """Test MLClassifier initialization"""
        classifier = MLClassifier()
        assert classifier is not None
        assert classifier.is_trained == False
    
    def test_prepare_training_data(self):
        """Test training data preparation"""
        classifier = MLClassifier()
        
        # Mock training data
        legitimate_features = [[0.1, 0.2, 0.3], [0.2, 0.3, 0.4]]
        fake_features = [[0.8, 0.9, 0.7], [0.9, 0.8, 0.9]]
        
        X, y = classifier.prepare_training_data(legitimate_features, fake_features)
        
        assert X.shape == (4, 3)
        assert y.shape == (4,)
        assert list(y) == [0, 0, 1, 1]  # 0 for legitimate, 1 for fake
    
    @patch('joblib.dump')
    def test_train_model(self, mock_dump):
        """Test model training"""
        classifier = MLClassifier()
        
        # Mock training data
        X = np.array([[0.1, 0.2], [0.2, 0.3], [0.8, 0.9], [0.9, 0.8]])
        y = np.array([0, 0, 1, 1])
        
        result = classifier.train_model(X, y)
        
        assert result['success'] == True
        assert 'accuracy' in result
        assert 'precision' in result
        assert 'recall' in result
        assert 'f1_score' in result
        assert classifier.is_trained == True
    
    def test_predict_untrained(self):
        """Test prediction with untrained model"""
        classifier = MLClassifier()
        
        features = [0.5, 0.6, 0.7]
        result = classifier.predict(features)
        
        assert result['is_fake'] == False
        assert result['confidence'] == 0.5
        assert result['fake_probability'] == 0.5
    
    def test_predict_trained(self):
        """Test prediction with trained model"""
        classifier = MLClassifier()
        
        # Mock trained model
        mock_model = Mock()
        mock_model.predict.return_value = [1]  # Fake
        mock_model.predict_proba.return_value = [[0.2, 0.8]]  # 80% fake probability
        
        classifier.model = mock_model
        classifier.is_trained = True
        
        features = [0.8, 0.9, 0.7]
        result = classifier.predict(features)
        
        assert result['is_fake'] == True
        assert result['confidence'] == 0.8
        assert result['fake_probability'] == 0.8
    
    @patch('joblib.load')
    def test_load_model(self, mock_load):
        """Test model loading"""
        classifier = MLClassifier()
        
        mock_model = Mock()
        mock_load.return_value = mock_model
        
        success = classifier.load_model('test_model.pkl')
        
        assert success == True
        assert classifier.model == mock_model
        assert classifier.is_trained == True
    
    def test_cross_validate(self):
        """Test cross validation"""
        classifier = MLClassifier()
        
        X = np.array([[0.1, 0.2], [0.2, 0.3], [0.8, 0.9], [0.9, 0.8]])
        y = np.array([0, 0, 1, 1])
        
        scores = classifier.cross_validate(X, y, cv=2)
        
        assert 'accuracy' in scores
        assert 'precision' in scores
        assert 'recall' in scores
        assert 'f1_score' in scores
        assert all(isinstance(score, (int, float)) for score in scores.values())
