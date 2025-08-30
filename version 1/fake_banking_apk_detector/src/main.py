import os
import sys
import argparse
import logging
from typing import Dict, Optional
import yaml

# Add src to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from detector.apk_analyzer import APKAnalyzer
from detector.feature_extractor import FeatureExtractor
from detector.ml_classifier import MLClassifier
from detector.signature_matcher import SignatureMatcher
from utils.logger import setup_logger
from utils.file_handler import FileHandler

class FakeBankingAPKDetector:
    """Main class for fake banking APK detection"""
    
    def __init__(self, config_path: str = 'config/config.yaml'):
        # Load configuration
        self.config = self._load_config(config_path)
        
        # Setup logging
        setup_logger(self.config['logging'])
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.apk_analyzer = APKAnalyzer()
        self.feature_extractor = FeatureExtractor()
        self.signature_matcher = SignatureMatcher('config/bank_signatures.json')
        self.ml_classifier = MLClassifier(self.config['ml_model']['algorithm'])
        self.file_handler = FileHandler()
        
        # Load trained model if available
        model_path = 'data/models/trained_model.joblib'
        if os.path.exists(model_path):
            try:
                self.ml_classifier.load_model(model_path)
                self.logger.info("Loaded pre-trained model")
            except Exception as e:
                self.logger.warning(f"Failed to load model: {str(e)}")
    
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Failed to load config: {str(e)}")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict:
        """Return default configuration"""
        return {
            'detector': {'confidence_threshold': 0.7},
            'ml_model': {'algorithm': 'random_forest'},
            'logging': {'level': 'INFO'}
        }
    
    def detect_fake_apk(self, apk_path: str) -> Dict:
        """
        Detect if an APK is a fake banking application
        
        Args:
            apk_path: Path to the APK file
            
        Returns:
            Detection results dictionary
        """
        try:
            self.logger.info(f"Analyzing APK: {apk_path}")
            
            # Validate file
            if not self.file_handler.validate_apk_file(apk_path):
                return {
                    'error': 'Invalid APK file',
                    'is_fake': None,
                    'confidence': 0.0
                }
            
            # Step 1: APK Analysis
            analysis_result = self.apk_analyzer.analyze_apk(apk_path)
            
            # Step 2: Signature Matching
            signature_result = self.signature_matcher.match_signatures(analysis_result)
            
            # Step 3: Feature Extraction
            features = self.feature_extractor.extract_features(analysis_result)
            
            # Step 4: ML Classification
            ml_result = {}
            if self.ml_classifier.is_trained:
                ml_result = self.ml_classifier.predict_single(features)
            else:
                self.logger.warning("ML classifier not trained, skipping ML prediction")
                ml_result = {'is_fake': False, 'confidence': 0.0, 'risk_level': 'UNKNOWN'}
            
            # Step 5: Combine Results
            final_result = self._combine_results(
                analysis_result, signature_result, ml_result, apk_path
            )
            
            self.logger.info(f"Detection completed for {apk_path}")
            return final_result
            
        except Exception as e:
            self.logger.error(f"Detection failed for {apk_path}: {str(e)}")
            return {
                'error': str(e),
                'is_fake': None,
                'confidence': 0.0,
                'apk_path': apk_path
            }
    
    def _combine_results(self, analysis_result: Dict, signature_result: Dict, 
                        ml_result: Dict, apk_path: str) -> Dict:
        """Combine results from different detection methods"""
        
        # Extract key information
        package_name = analysis_result.get('manifest_info', {}).get('package_name', 'Unknown')
        
        # Signature-based decision
        signature_fake_prob = signature_result.get('signature_score', {}).get('fake_probability', 0.5)
        signature_confidence = signature_result.get('confidence', 0.0)
        
        # ML-based decision
        ml_fake_prob = ml_result.get('confidence', 0.5)
        ml_confidence = 0.8 if self.ml_classifier.is_trained else 0.0
        
        # Weighted combination
        total_weight = signature_confidence + ml_confidence
        
        if total_weight > 0:
                        combined_fake_prob = (
                (signature_fake_prob * signature_confidence + ml_fake_prob * ml_confidence) 
                / total_weight
            )
            combined_confidence = min((signature_confidence + ml_confidence) / 2, 1.0)
        else:
            # Fallback to signature result if no ML model
            combined_fake_prob = signature_fake_prob
            combined_confidence = max(signature_confidence, 0.3)
        
        # Apply confidence threshold
        threshold = self.config['detector']['confidence_threshold']
        is_fake = combined_fake_prob >= threshold
        
        # Determine risk level
        risk_level = self._determine_risk_level(combined_fake_prob, combined_confidence)
        
        # Compile detailed result
        result = {
            'apk_path': apk_path,
            'package_name': package_name,
            'is_fake': is_fake,
            'fake_probability': combined_fake_prob,
            'confidence': combined_confidence,
            'risk_level': risk_level,
            'detection_methods': {
                'signature_analysis': {
                    'is_known_legitimate': signature_result.get('is_known_legitimate', False),
                    'is_suspicious_pattern': signature_result.get('is_suspicious_pattern', False),
                    'fake_probability': signature_fake_prob,
                    'confidence': signature_confidence,
                    'matched_bank': signature_result.get('legitimate_match', {}).get('bank'),
                    'suspicious_indicators': signature_result.get('suspicious_match', {}).get('indicators', [])
                },
                'ml_analysis': {
                    'is_fake': ml_result.get('is_fake', False),
                    'confidence': ml_result.get('confidence', 0.0),
                    'risk_level': ml_result.get('risk_level', 'UNKNOWN'),
                    'model_available': self.ml_classifier.is_trained
                }
            },
            'apk_details': {
                'file_size': analysis_result.get('file_info', {}).get('size', 0),
                'md5_hash': analysis_result.get('file_info', {}).get('md5', ''),
                'permissions_count': len(analysis_result.get('permissions', [])),
                'activities_count': len(analysis_result.get('activities', [])),
                'has_certificate': bool(analysis_result.get('certificate_info', {}))
            },
            'recommendations': self._generate_recommendations(
                is_fake, combined_fake_prob, signature_result, ml_result
            ),
            'timestamp': self._get_timestamp()
        }
        
        return result
    
    def _determine_risk_level(self, fake_probability: float, confidence: float) -> str:
        """Determine overall risk level"""
        if fake_probability >= 0.8 and confidence >= 0.7:
            return 'CRITICAL'
        elif fake_probability >= 0.6 and confidence >= 0.5:
            return 'HIGH'
        elif fake_probability >= 0.4 and confidence >= 0.3:
            return 'MEDIUM'
        elif fake_probability >= 0.2:
            return 'LOW'
        else:
            return 'VERY_LOW'
    
    def _generate_recommendations(self, is_fake: bool, fake_probability: float,
                                signature_result: Dict, ml_result: Dict) -> List[str]:
        """Generate user recommendations based on detection results"""
        recommendations = []
        
        if is_fake:
            recommendations.append("⚠️ DO NOT INSTALL this APK - it appears to be a fake banking application")
            recommendations.append("🚫 Uninstall immediately if already installed")
            recommendations.append("🔒 Change your banking passwords and PINs as a precaution")
            recommendations.append("📞 Contact your bank to report this suspicious application")
        elif fake_probability >= 0.3:
            recommendations.append("⚠️ Exercise caution - this APK shows some suspicious characteristics")
            recommendations.append("✅ Verify the APK source and download only from official app stores")
            recommendations.append("🔍 Check the developer information and user reviews")
        else:
            recommendations.append("✅ This APK appears to be legitimate")
            recommendations.append("🔒 Still recommended to download only from official sources")
        
        # Add specific recommendations based on detection methods
        if signature_result.get('is_suspicious_pattern'):
            indicators = signature_result.get('suspicious_match', {}).get('indicators', [])
            if indicators:
                recommendations.append(f"🔍 Suspicious patterns detected: {', '.join(indicators[:3])}")
        
        if signature_result.get('is_known_legitimate'):
            bank = signature_result.get('legitimate_match', {}).get('bank')
            if bank:
                recommendations.append(f"✅ Matches signature of legitimate {bank} application")
        
        return recommendations
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def batch_detect(self, apk_directory: str) -> Dict:
        """
        Detect fake APKs in a directory
        
        Args:
            apk_directory: Directory containing APK files
            
        Returns:
            Batch detection results
        """
        try:
            apk_files = self.file_handler.find_apk_files(apk_directory)
            
            if not apk_files:
                return {
                    'error': 'No APK files found in directory',
                    'results': []
                }
            
            results = []
            fake_count = 0
            
            self.logger.info(f"Starting batch detection for {len(apk_files)} APK files")
            
            for i, apk_file in enumerate(apk_files, 1):
                self.logger.info(f"Processing {i}/{len(apk_files)}: {apk_file}")
                
                result = self.detect_fake_apk(apk_file)
                results.append(result)
                
                if result.get('is_fake'):
                    fake_count += 1
            
            batch_result = {
                'total_apks': len(apk_files),
                'fake_apks_detected': fake_count,
                'legitimate_apks': len(apk_files) - fake_count,
                'fake_percentage': (fake_count / len(apk_files)) * 100 if apk_files else 0,
                'results': results,
                'summary': self._generate_batch_summary(results)
            }
            
            self.logger.info(f"Batch detection completed: {fake_count}/{len(apk_files)} fake APKs detected")
            return batch_result
            
        except Exception as e:
            self.logger.error(f"Batch detection failed: {str(e)}")
            return {
                'error': str(e),
                'results': []
            }
    
    def _generate_batch_summary(self, results: List[Dict]) -> Dict:
        """Generate summary statistics for batch detection"""
        if not results:
            return {}
        
        risk_levels = {}
        avg_confidence = 0
        errors = 0
        
        for result in results:
            if 'error' in result:
                errors += 1
                continue
            
            risk_level = result.get('risk_level', 'UNKNOWN')
            risk_levels[risk_level] = risk_levels.get(risk_level, 0) + 1
            avg_confidence += result.get('confidence', 0)
        
        valid_results = len(results) - errors
        
        return {
            'risk_level_distribution': risk_levels,
            'average_confidence': avg_confidence / valid_results if valid_results > 0 else 0,
            'errors': errors,
            'success_rate': (valid_results / len(results)) * 100 if results else 0
        }

def main():
    """Main function for command-line interface"""
    parser = argparse.ArgumentParser(description='Fake Banking APK Detector')
    parser.add_argument('input', help='APK file or directory path')
    parser.add_argument('--config', default='config/config.yaml', help='Configuration file path')
    parser.add_argument('--output', help='Output file for results (JSON format)')
    parser.add_argument('--batch', action='store_true', help='Batch mode for directory processing')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    try:
        # Initialize detector
        detector = FakeBankingAPKDetector(args.config)
        
        # Process input
        if args.batch or os.path.isdir(args.input):
            results = detector.batch_detect(args.input)
        else:
            results = detector.detect_fake_apk(args.input)
        
        # Output results
        if args.output:
            import json
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"Results saved to {args.output}")
        
        # Print summary
        if args.batch or os.path.isdir(args.input):
            print(f"\nBatch Detection Summary:")
            print(f"Total APKs: {results.get('total_apks', 0)}")
            print(f"Fake APKs detected: {results.get('fake_apks_detected', 0)}")
            print(f"Fake percentage: {results.get('fake_percentage', 0):.1f}%")
        else:
            print(f"\nDetection Result for {args.input}:")
            print(f"Package: {results.get('package_name', 'Unknown')}")
            print(f"Is Fake: {results.get('is_fake', 'Unknown')}")
            print(f"Confidence: {results.get('confidence', 0):.2f}")
            print(f"Risk Level: {results.get('risk_level', 'Unknown')}")
            
            if args.verbose:
                recommendations = results.get('recommendations', [])
                if recommendations:
                    print("\nRecommendations:")
                    for rec in recommendations:
                        print(f"  {rec}")
    
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()

                
