import os
import sys
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import logging
import joblib
from typing import Tuple, Dict, List

# Add src to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detector.apk_analyzer import APKAnalyzer
from detector.feature_extractor import FeatureExtractor
from detector.ml_classifier import MLClassifier
from utils.logger import setup_logger
from utils.file_handler import FileHandler

class ModelTrainer:
    """Train machine learning models for fake APK detection"""
    
    def __init__(self):
        # Setup logging
        setup_logger({'level': 'INFO', 'file': 'logs/training.log'})
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.apk_analyzer = APKAnalyzer()
        self.feature_extractor = FeatureExtractor()
        self.file_handler = FileHandler()
        
        # Data storage
        self.features = []
        self.labels = []
        self.apk_paths = []
    
    def prepare_training_data(self, legitimate_dir: str, fake_dir: str) -> Tuple[np.ndarray, np.ndarray]:
        """
        Prepare training data from legitimate and fake APK directories
        
        Args:
            legitimate_dir: Directory containing legitimate banking APKs
            fake_dir: Directory containing fake banking APKs
            
        Returns:
            Tuple of (features, labels)
        """
        try:
            self.logger.info("Preparing training data...")
            
            # Process legitimate APKs
            legitimate_apks = self.file_handler.find_apk_files(legitimate_dir)
            self.logger.info(f"Found {len(legitimate_apks)} legitimate APKs")
            
            for apk_path in legitimate_apks:
                try:
                    features = self._extract_features_from_apk(apk_path)
                    if features is not None:
                        self.features.append(features)
                        self.labels.append(0)  # 0 for legitimate
                        self.apk_paths.append(apk_path)
                except Exception as e:
                    self.logger.error(f"Failed to process {apk_path}: {str(e)}")
            
            # Process fake APKs
            fake_apks = self.file_handler.find_apk_files(fake_dir)
            self.logger.info(f"Found {len(fake_apks)} fake APKs")
            
            for apk_path in fake_apks:
                try:
                    features = self._extract_features_from_apk(apk_path)
                    if features is not None:
                        self.features.append(features)
                        self.labels.append(1)  # 1 for fake
                        self.apk_paths.append(apk_path)
                except Exception as e:
                    self.logger.error(f"Failed to process {apk_path}: {str(e)}")
            
            if not self.features:
                raise ValueError("No features extracted from APK files")
            
            # Convert to numpy arrays
            X = np.array(self.features)
            y = np.array(self.labels)
            
            self.logger.info(f"Training data prepared: {X.shape[0]} samples, {X.shape[1]} features")
            self.logger.info(f"Class distribution - Legitimate: {np.sum(y == 0)}, Fake: {np.sum(y == 1)}")
            
            return X, y
            
        except Exception as e:
            self.logger.error(f"Training data preparation failed: {str(e)}")
            raise
    
    def _extract_features_from_apk(self, apk_path: str) -> np.ndarray:
        """Extract features from a single APK"""
        try:
            # Analyze APK
            analysis_result = self.apk_analyzer.analyze_apk(apk_path)
            
            # Extract features
            features = self.feature_extractor.extract_features(analysis_result)
            
            return features
            
        except Exception as e:
            self.logger.error(f"Feature extraction failed for {apk_path}: {str(e)}")
            return None
    
    def train_models(self, X: np.ndarray, y: np.ndarray) -> Dict:
        """
        Train multiple ML models and compare performance
        
        Args:
            X: Feature matrix
            y: Labels
            
        Returns:
            Training results for all models
        """
        model_types = ['random_forest', 'gradient_boosting', 'svm', 'logistic_regression']
        results = {}
        
        feature_names = self.feature_extractor.get_feature_names()
        
        for model_type in model_types:
            try:
                self.logger.info(f"Training {model_type} model...")
                
                # Initialize classifier
                classifier = MLClassifier(model_type)
                
                # Train model
                training_metrics = classifier.train(X, y, feature_names)
                
                # Save model
                model_path = f'data/models/{model_type}_model.joblib'
                os.makedirs(os.path.dirname(model_path), exist_ok=True)
                classifier.save_model(model_path)
                
                # Store results
                results[model_type] = {
                    'metrics': training_metrics,
                    'model_path': model_path,
                    'feature_importance': classifier.get_feature_importance()
                }
                
                self.logger.info(f"{model_type} training completed - Accuracy: {training_metrics['test_accuracy']:.4f}")
                
            except Exception as e:
                self.logger.error(f"Training failed for {model_type}: {str(e)}")
                results[model_type] = {'error': str(e)}
        
        return results
    
    def hyperparameter_tuning(self, X: np.ndarray, y: np.ndarray, model_type: str = 'random_forest') -> Dict:
        """
        Perform hyperparameter tuning for a specific model
        
        Args:
            X: Feature matrix
            y: Labels
            model_type: Type of model to tune
            
        Returns:
            Tuning results
        """
        try:
            self.logger.info(f"Starting hyperparameter tuning for {model_type}...")
            
            classifier = MLClassifier(model_type)
            tuning_results = classifier.hyperparameter_tuning(X, y)
            
            # Save tuned model
            model_path = f'data/models/{model_type}_tuned_model.joblib'
            os.makedirs(os.path.dirname(model_path), exist_ok=True)
            classifier.save_model(model_path)
            
            tuning_results['model_path'] = model_path
            
            self.logger.info(f"Hyperparameter tuning completed - Best score: {tuning_results['best_score']:.4f}")
            return tuning_results
            
        except Exception as e:
            self.logger.error(f"Hyperparameter tuning failed: {str(e)}")
            raise
    
    def evaluate_model(self, model_path: str, test_X: np.ndarray, test_y: np.ndarray) -> Dict:
        """
        Evaluate a trained model on test data
        
        Args:
            model_path: Path to saved model
            test_X: Test features
            test_y: Test labels
            
        Returns:
            Evaluation metrics
        """
        try:
            # Load model
            classifier = MLClassifier()
            classifier.load_model(model_path)
            
            # Evaluate
            metrics = classifier.evaluate_model(test_X, test_y)
            
            self.logger.info(f"Model evaluation completed - Accuracy: {metrics['accuracy']:.4f}")
            return metrics
            
        except Exception as e:
            self.logger.error(f"Model evaluation failed: {str(e)}")
            raise
    
    def generate_training_report(self, results: Dict) -> str:
        """Generate comprehensive training report"""
        report_lines = []
        report_lines.append("=" * 60)
        report_lines.append("FAKE BANKING APK DETECTOR - TRAINING REPORT")
        report_lines.append("=" * 60)
        report_lines.append("")
        
        # Dataset summary
        total_samples = len(self.features)
        legitimate_count = np.sum(np.array(self.labels) == 0)
        fake_count = np.sum(np.array(self.labels) == 1)
        
        report_lines.append("DATASET SUMMARY:")
        report_lines.append(f"Total samples: {total_samples}")
        report_lines.append(f"Legitimate APKs: {legitimate_count} ({legitimate_count/total_samples*100:.1f}%)")
        report_lines.append(f"Fake APKs: {fake_count} ({fake_count/total_samples*100:.1f}%)")
        report_lines.append("")
        
        # Model performance comparison
        report_lines.append("MODEL PERFORMANCE COMPARISON:")
        report_lines.append("-" * 40)
        
        for model_type, result in results.items():
            if 'error' in result:
                report_lines.append(f"{model_type}: FAILED - {result['error']}")
            else:
                metrics = result['metrics']
                report_lines.append(f"{model_type}:")
                report_lines.append(f"  Test Accuracy: {metrics['test_accuracy']:.4f}")
                report_lines.append(f"  AUC Score: {metrics['auc_score']:.4f}")
                report_lines.append(f"  CV Mean: {metrics['cv_mean']:.4f} (±{metrics['cv_std']:.4f})")
        
        report_lines.append("")
        
        # Best model recommendation
        best_model = None
        best_score = 0
        
        for model_type, result in results.items():
            if 'error' not in result:
                score = result['metrics']['test_accuracy']
                if score > best_score:
                    best_score = score
                    best_model = model_type
        
        if best_model:
            report_lines.append(f"RECOMMENDED MODEL: {best_model} (Accuracy: {best_score:.4f})")
            
            # Feature importance for best model
            importance = results[best_model].get('feature_importance', {})
            if importance:
                report_lines.append("")
                report_lines.append("TOP 10 IMPORTANT FEATURES:")
                report_lines.append("-" * 30)
                
                sorted_features = sorted(importance.items(), key=lambda x: x[1], reverse=True)
                for i, (feature, score) in enumerate(sorted_features[:10], 1):
                    report_lines.append(f"{i:2d}. {feature}: {score:.4f}")
        
        report_lines.append("")
        report_lines.append("=" * 60)
        
        return "\n".join(report_lines)
    
    def save_training_data(self, X: np.ndarray, y: np.ndarray, filepath: str):
        """Save training data for future use"""
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            training_data = {
                'features': X,
                'labels': y,
                'apk_paths': self.apk_paths,
                'feature_names': self.feature_extractor.get_feature_names()
            }
            
            joblib.dump(training_data, filepath)
            self.logger.info(f"Training data saved to {filepath}")
            
        except Exception as e:
            self.logger.error(f"Failed to save training data: {str(e)}")
            raise

def main():
    """Main function for model training"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Train Fake Banking APK Detection Models')
    parser.add_argument('--legitimate-dir', required=True, help='Directory with legitimate APKs')
    parser.add_argument('--fake-dir', required=True, help='Directory with fake APKs')
    parser.add_argument('--output-dir', default='data/models', help='Output directory for models')
    parser.add_argument('--tune', action='store_true', help='Perform hyperparameter tuning')
    parser.add_argument('--model-type', default='random_forest', help='Model type for tuning')
    
    args = parser.parse_args()
    
    try:
        # Initialize trainer
        trainer = ModelTrainer()
        
        # Prepare training data
        X, y = trainer.prepare_training_data(args.legitimate_dir, args.fake_dir)
        
        # Save training data
        trainer.save_training_data(X, y, os.path.join(args.output_dir, 'training_data.joblib'))
        
        # Train models
        results = trainer.train_models(X, y)
        
        # Hyperparameter tuning if requested
        if args.tune:
            tuning_results = trainer.hyperparameter_tuning(X, y, args.model_type)
            results[f'{args.model_type}_tuned'] = {'metrics': tuning_results}
        
        # Generate and save report
        report = trainer.generate_training_report(results)
        
        report_path = os.path.join(args.output_dir, 'training_report.txt')
        with open(report_path, 'w') as f:
            f.write(report)
        
        print(report)
        print(f"\nTraining completed. Models saved to {args.output_dir}")
        print(f"Training report saved to {report_path}")
        
    except Exception as e:
        print(f"Training failed: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()
