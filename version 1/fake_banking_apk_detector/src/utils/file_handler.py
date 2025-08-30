import os
import zipfile
import magic
from typing import List, Optional
import logging

class FileHandler:
    """Handle file operations and validation"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.max_file_size = 100 * 1024 * 1024  # 100MB
    
    def validate_apk_file(self, file_path: str) -> bool:
        """
        Validate if file is a valid APK
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if valid APK, False otherwise
        """
        try:
            # Check if file exists
            if not os.path.exists(file_path):
                self.logger.error(f"File not found: {file_path}")
                return False
            
            # Check file size
            file_size = os.path.getsize(file_path)
            if file_size > self.max_file_size:
                self.logger.error(f"File too large: {file_size} bytes")
                return False
            
            if file_size == 0:
                self.logger.error("File is empty")
                return False
            
            # Check file extension
            if not file_path.lower().endswith('.apk'):
                self.logger.warning(f"File doesn't have .apk extension: {file_path}")
            
            # Check if it's a valid ZIP file (APK is a ZIP)
            try:
                with zipfile.ZipFile(file_path, 'r') as zip_file:
                    # Check for required APK files
                    file_list = zip_file.namelist()
                    
                    required_files = ['AndroidManifest.xml']
                    for required_file in required_files:
                        if required_file not in file_list:
                            self.logger.error(f"Missing required file: {required_file}")
                            return False
                    
                    # Test ZIP integrity
                    zip_file.testzip()
                    
            except zipfile.BadZipFile:
                self.logger.error(f"Invalid ZIP/APK file: {file_path}")
                return False
            except Exception as e:
                self.logger.error(f"ZIP validation failed: {str(e)}")
                return False
            
            # Additional MIME type check if python-magic is available
            try:
                file_type = magic.from_file(file_path, mime=True)
                if file_type not in ['application/zip', 'application/java-archive', 
                                   'application/vnd.android.package-archive']:
                    self.logger.warning(f"Unexpected MIME type: {file_type}")
            except:
                # python-magic not available, skip this check
                pass
            
            return True
            
        except Exception as e:
            self.logger.error(f"File validation failed: {str(e)}")
            return False
    
    def find_apk_files(self, directory: str) -> List[str]:
        """
        Find all APK files in a directory
        
        Args:
            directory: Directory to search
            
        Returns:
            List of APK file paths
        """
        apk_files = []
        
        try:
            if not os.path.exists(directory):
                self.logger.error(f"Directory not found: {directory}")
                return apk_files
            
            if not os.path.isdir(directory):
                self.logger.error(f"Path is not a directory: {directory}")
                return apk_files
            
            # Walk through directory
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if file.lower().endswith('.apk'):
                        file_path = os.path.join(root, file)
                        if self.validate_apk_file(file_path):
                            apk_files.append(file_path)
                        else:
                            self.logger.warning(f"Invalid APK skipped: {file_path}")
            
            self.logger.info(f"Found {len(apk_files)} valid APK files in {directory}")
            return apk_files
            
        except Exception as e:
            self.logger.error(f"Directory search failed: {str(e)}")
            return apk_files
    
    def create_directory(self, directory: str) -> bool:
        """Create directory if it doesn't exist"""
        try:
            if not os.path.exists(directory):
                os.makedirs(directory)
                self.logger.info(f"Created directory: {directory}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to create directory {directory}: {str(e)}")
            return False
    
    def safe_filename(self, filename: str) -> str:
        """Generate safe filename by removing invalid characters"""
        import re
        # Remove invalid characters
        safe_name = re.sub(r'[<>:"/\\|?*]', '_', filename)
        # Limit length
        if len(safe_name) > 200:
            safe_name = safe_name[:200]
        return safe_name
