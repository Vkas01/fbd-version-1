import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.preprocessing import StandardScaler
import joblib
import logging
from typing import Dict, List, Tuple, Any
import os

class MLClassifier:
    """Machine Learning classifier for fake banking APK detection"""
    
    def __init__(self, model_type: str = 'random_forest'):
        self.logger = logging.getLogger(__name__)
        self.model_type = model_type
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = []
        
        # Initialize model based on type
        self._initialize_model()
    
    def _initialize_model(self):
        """Initialize the ML model based on type"""
        if self.model_type == 'random_forest':
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1
            )
        elif self.model_type == 'gradient_boosting':
            self.model = GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=6,
                random_state=42
            )
        elif self.model_type == 'svm':
            self.model = SVC(
                kernel='rbf',
                C=1.0,
                gamma='scale',
                probability=True,
                random_state=42
            )
        elif self.model_type == 'logistic_regression':
            self.model = LogisticRegression(
                C=1.0,
                max_iter=1000,
                random_state=42
            )
        else:
            raise ValueError(f"Unsupported model type: {self.model_type}")
    
    def train(self, X: np.ndarray, y: np.ndarray, feature_names: List[str] = None) -> Dict:
        """
        Train the classifier
        
        Args:
            X: Feature matrix
            y: Labels (0 for legitimate, 1 for fake)
            feature_names: Names of features
            
        Returns:
            Training metrics
        """
        try:
            self.logger.info(f"Training {self.model_type} classifier...")
            
            if feature_names:
                self.feature_names = feature_names
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train model
            self.model.fit(X_train_scaled, y_train)
            
            # Evaluate
            train_score = self.model.score(X_train_scaled, y_train)
            test_score = self.model.score(X_test_scaled, y_test)
            
            # Predictions for detailed metrics
            y_pred = self.model.predict(X_test_scaled)
            y_pred_proba = self.model.predict_proba(X_test_scaled)[:, 1]
            
            # Calculate metrics
            auc_score = roc_auc_score(y_test, y_pred_proba)
            
            # Cross-validation
            cv_scores = cross_val_score(
                self.model, X_train_scaled, y_train, cv=5, scoring='accuracy'
            )
            
            self.is_trained = True
            
            metrics = {
                'train_accuracy': train_score,
                'test_accuracy': test_score,
                'auc_score': auc_score,
                'cv_mean': cv_scores.mean(),
                'cv_std': cv_scores.std(),
                'classification_report': classification_report(y_test, y_pred),
                'confusion_matrix': confusion_matrix(y_test, y_pred).tolist()
            }
            
            self.logger.info(f"Training completed. Test accuracy: {test_score:.4f}")
            return metrics
            
        except Exception as e:
            self.logger.error(f"Training failed: {str(e)}")
            raise
    
    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Make predictions
        
        Args:
            X: Feature matrix
            
        Returns:
            Tuple of (predictions, probabilities)
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        try:
            X_scaled = self.scaler.transform(X)
            predictions = self.model.predict(X_scaled)
            probabilities = self.model.predict_proba(X_scaled)
            
            return predictions, probabilities
            
        except Exception as e:
            self.logger.error(f"Prediction failed: {str(e)}")
            raise
    
    def predict_single(self, features: np.ndarray) -> Dict:
        """
        Predict for a single APK
        
        Args:
            features: Feature vector
            
        Returns:
            Prediction result dictionary
        """
        if features.ndim == 1:
            features = features.reshape(1, -1)
        
        predictions, probabilities = self.predict(features)
        
        result = {
            'is_fake': bool(predictions[0]),
            'confidence': float(probabilities[0][1]),  # Probability of being fake
            'risk_level': self._get_risk_level(probabilities[0][1])
        }
        
        return result
    
    def _get_risk_level(self, fake_probability: float) -> str:
        """Determine risk level based on probability"""
        if fake_probability >= 0.8:
            return 'HIGH'
        elif fake_probability >= 0.6:
            return 'MEDIUM'
        elif fake_probability >= 0.3:
            return 'LOW'
        else:
            return 'VERY_LOW'
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance (for tree-based models)"""
        if not self.is_trained:
            raise ValueError("Model must be trained first")
        
        if hasattr(self.model, 'feature_importances_'):
            importance_dict = {}
            importances = self.model.feature_importances_
            
            for i, importance in enumerate(importances):
                feature_name = (self.feature_names[i] if i < len(self.feature_names) 
                              else f'feature_{i}')
                importance_dict[feature_name] = float(importance)
            
            # Sort by importance
            return dict(sorted(importance_dict.items(), 
                             key=lambda x: x[1], reverse=True))
        else:
            self.logger.warning("Model doesn't support feature importance")
            return {}
    
    def hyperparameter_tuning(self, X: np.ndarray, y: np.ndarray) -> Dict:
        """
        Perform hyperparameter tuning
        
        Args:
            X: Feature matrix
            y: Labels
            
        Returns:
            Best parameters and score
        """
        self.logger.info("Starting hyperparameter tuning...")
        
        # Define parameter grids for different models
        param_grids = {
            'random_forest': {
                'n_estimators': [50, 100, 200],
                'max_depth': [5, 10, 15, None],
                'min_samples_split': [2, 5, 10],
                'min_samples_leaf': [1, 2, 4]
            },
            'gradient_boosting': {
                'n_estimators': [50, 100, 200],
                'learning_rate': [0.01, 0.1, 0.2],
                'max_depth': [3, 6, 9]
            },
            'svm': {
                'C': [0.1, 1, 10],
                'gamma': ['scale', 'auto', 0.001, 0.01],
                'kernel': ['rbf', 'poly']
            },
            'logistic_regression': {
                'C': [0.01, 0.1, 1, 10, 100],
                'penalty': ['l1', 'l2'],
                'solver': ['liblinear', 'saga']
            }
        }
        
        param_grid = param_grids.get(self.model_type, {})
        
        if not param_grid:
            self.logger.warning(f"No parameter grid defined for {self.model_type}")
            return {}
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Grid search
        grid_search = GridSearchCV(
            self.model,
            param_grid,
            cv=5,
            scoring='accuracy',
            n_jobs=-1,
            verbose=1
        )
        
        grid_search.fit(X_scaled, y)
        
        # Update model with best parameters
        self.model = grid_search.best_estimator_
        self.is_trained = True
        
        results = {
            'best_params': grid_search.best_params_,
            'best_score': grid_search.best_score_,
            'cv_results': grid_search.cv_results_
        }
        
        self.logger.info(f"Best parameters: {grid_search.best_params_}")
        self.logger.info(f"Best score: {grid_search.best_score_:.4f}")
        
        return results
    
    def save_model(self, filepath: str):
        """Save trained model to file"""
        if not self.is_trained:
            raise ValueError("No trained model to save")
        
        try:
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'model_type': self.model_type,
                'feature_names': self.feature_names,
                'is_trained': self.is_trained
            }
            
            joblib.dump(model_data, filepath)
            self.logger.info(f"Model saved to {filepath}")
            
        except Exception as e:
            self.logger.error(f"Failed to save model: {str(e)}")
            raise
    
    def load_model(self, filepath: str):
        """Load trained model from file"""
        try:
            if not os.path.exists(filepath):
                raise FileNotFoundError(f"Model file not found: {filepath}")
            
            model_data = joblib.load(filepath)
            
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.model_type = model_data['model_type']
            self.feature_names = model_data.get('feature_names', [])
            self.is_trained = model_data.get('is_trained', True)
            
            self.logger.info(f"Model loaded from {filepath}")
            
        except Exception as e:
            self.logger.error(f"Failed to load model: {str(e)}")
            raise
    
    def evaluate_model(self, X: np.ndarray, y: np.ndarray) -> Dict:
        """
        Evaluate model performance
        
        Args:
            X: Feature matrix
            y: True labels
            
        Returns:
            Evaluation metrics
        """
        if not self.is_trained:
            raise ValueError("Model must be trained first")
        
        try:
            X_scaled = self.scaler.transform(X)
            
            # Predictions
            y_pred = self.model.predict(X_scaled)
            y_pred_proba = self.model.predict_proba(X_scaled)[:, 1]
            
            # Calculate metrics
            accuracy = self.model.score(X_scaled, y)
            auc_score = roc_auc_score(y, y_pred_proba)
            
            # Detailed classification report
            class_report = classification_report(y, y_pred, output_dict=True)
            conf_matrix = confusion_matrix(y, y_pred)
            
            metrics = {
                'accuracy': accuracy,
                'auc_score': auc_score,
                'precision': class_report['1']['precision'],
                'recall': class_report['1']['recall'],
                'f1_score': class_report['1']['f1-score'],
                'confusion_matrix': conf_matrix.tolist(),
                'classification_report': classification_report(y, y_pred)
            }
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Model evaluation failed: {str(e)}")
            raise
