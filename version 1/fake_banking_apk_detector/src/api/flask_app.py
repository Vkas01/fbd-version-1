from flask import Flask, request, jsonify, render_template, send_file
import os
import sys
import tempfile
import uuid
from werkzeug.utils import secure_filename
import logging

# Add src to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import FakeBankingAPKDetector
from utils.file_handler import FileHandler

app = Flask(__name__, template_folder='../../web_interface/templates', 
           static_folder='../../web_interface/static')
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
app.secret_key = 'your-secret-key-here'  # Change this in production

# Initialize detector
detector = FakeBankingAPKDetector()
file_handler = FileHandler()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/api/detect', methods=['POST'])
def detect_apk():
    """API endpoint for APK detection"""
    try:
        # Check if file was uploaded
        if 'apk_file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['apk_file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Validate file
        if not file.filename.lower().endswith('.apk'):
            return jsonify({'error': 'File must be an APK'}), 400
        
        # Save uploaded file
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        file.save(file_path)
        
        try:
            # Validate APK file
            if not file_handler.validate_apk_file(file_path):
                return jsonify({'error': 'Invalid APK file'}), 400
            
            # Perform detection
            result = detector.detect_fake_apk(file_path)
            
            # Clean up uploaded file
            os.remove(file_path)
            
            # Format response
            response = {
                'success': True,
                'result': {
                    'filename': filename,
                    'package_name': result.get('package_name', 'Unknown'),
                    'is_fake': result.get('is_fake', False),
                    'confidence': result.get('confidence', 0.0),
                    'risk_level': result.get('risk_level', 'UNKNOWN'),
                    'fake_probability': result.get('fake_probability', 0.0),
                    'recommendations': result.get('recommendations', []),
                    'detection_methods': result.get('detection_methods', {}),
                    'apk_details': result.get('apk_details', {})
                }
            }
            
            return jsonify(response)
            
        except Exception as e:
            # Clean up file on error
            if os.path.exists(file_path):
                os.remove(file_path)
            raise e
            
    except Exception as e:
        logger.error(f"Detection API error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/batch-detect', methods=['POST'])
def batch_detect_apks():
    """API endpoint for batch APK detection"""
    try:
        # Check if files were uploaded
        if 'apk_files' not in request.files:
            return jsonify({'error': 'No files uploaded'}), 400
        
        files = request.files.getlist('apk_files')
        
        if not files or all(f.filename == '' for f in files):
            return jsonify({'error': 'No files selected'}), 400
        
        # Create temporary directory for batch processing
        temp_dir = tempfile.mkdtemp()
        uploaded_files = []
        
        try:
            # Save all uploaded files
            for file in files:
                if file.filename and file.filename.lower().endswith('.apk'):
                    filename = secure_filename(file.filename)
                    unique_filename = f"{uuid.uuid4()}_{filename}"
                    file_path = os.path.join(temp_dir, unique_filename)
                    file.save(file_path)
                    uploaded_files.append((file_path, filename))
            
            if not uploaded_files:
                return jsonify({'error': 'No valid APK files found'}), 400
            
            # Perform batch detection
            batch_result = detector.batch_detect(temp_dir)
            
            # Format response
            response = {
                'success': True,
                'result': {
                    'total_apks': batch_result.get('total_apks', 0),
                    'fake_apks_detected': batch_result.get('fake_apks_detected', 0),
                    'legitimate_apks': batch_result.get('legitimate_apks', 0),
                    'fake_percentage': batch_result.get('fake_percentage', 0),
                    'summary': batch_result.get('summary', {}),
                    'results': []
                }
            }
            
            # Add individual results with original filenames
            for i, (file_path, original_filename) in enumerate(uploaded_files):
                if i < len(batch_result.get('results', [])):
                    result = batch_result['results'][i].copy()
                    result['original_filename'] = original_filename
                    response['result']['results'].append(result)
            
            return jsonify(response)
            
        finally:
            # Clean up temporary files
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
            
    except Exception as e:
        logger.error(f"Batch detection API error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    try:
        # Check if ML model is loaded
        model_status = detector.ml_classifier.is_trained
        
        return jsonify({
            'status': 'healthy',
            'ml_model_loaded': model_status,
            'version': '1.0.0'
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500

@app.route('/api/stats')
def get_stats():
    """Get detection statistics"""
    # This would typically come from a database
    # For now, return mock statistics
    return jsonify({
        'total_detections': 1250,
        'fake_apks_detected': 89,
        'detection_rate': 7.1,
        'last_updated': '2024-01-15T10:30:00Z'
    })

@app.errorhandler(413)
def too_large(e):
    """Handle file too large error"""
    return jsonify({'error': 'File too large. Maximum size is 100MB.'}), 413

@app.errorhandler(500)
def internal_error(e):
    """Handle internal server error"""
    logger.error(f"Internal server error: {str(e)}")
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
