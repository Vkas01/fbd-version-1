// Fake Banking APK Detector - Frontend JavaScript

class APKDetector {
    constructor() {
        this.initializeEventListeners();
        this.loadStatistics();
        this.currentResults = null;
    }

    initializeEventListeners() {
        // Single file upload
        const singleFileInput = document.getElementById('singleFileInput');
        const singleUploadArea = document.getElementById('singleUploadArea');
        const analyzeSingleBtn = document.getElementById('analyzeSingleBtn');

        // Batch file upload
        const batchFileInput = document.getElementById('batchFileInput');
        const batchUploadArea = document.getElementById('batchUploadArea');
        const analyzeBatchBtn = document.getElementById('analyzeBatchBtn');

        // Single file events
        singleFileInput.addEventListener('change', (e) => this.handleSingleFileSelect(e));
        singleUploadArea.addEventListener('click', () => singleFileInput.click());
        singleUploadArea.addEventListener('dragover', (e) => this.handleDragOver(e));
        singleUploadArea.addEventListener('drop', (e) => this.handleSingleFileDrop(e));
        analyzeSingleBtn.addEventListener('click', () => this.analyzeSingleFile());

        // Batch file events
        batchFileInput.addEventListener('change', (e) => this.handleBatchFileSelect(e));
        batchUploadArea.addEventListener('click', () => batchFileInput.click());
        batchUploadArea.addEventListener('dragover', (e) => this.handleDragOver(e));
        batchUploadArea.addEventListener('drop', (e) => this.handleBatchFileDrop(e));
        analyzeBatchBtn.addEventListener('click', () => this.analyzeBatchFiles());
    }

    handleDragOver(e) {
        e.preventDefault();
        e.currentTarget.classList.add('dragover');
    }

    handleSingleFileDrop(e) {
        e.preventDefault();
        e.currentTarget.classList.remove('dragover');
        
        const files = e.dataTransfer.files;
        if (files.length > 0 && files[0].name.toLowerCase().endsWith('.apk')) {
            document.getElementById('singleFileInput').files = files;
            this.handleSingleFileSelect({ target: { files: files } });
        }
    }

    handleBatchFileDrop(e) {
        e.preventDefault();
        e.currentTarget.classList.remove('dragover');
        
        const files = Array.from(e.dataTransfer.files).filter(f => 
            f.name.toLowerCase().endsWith('.apk')
        );
        
        if (files.length > 0) {
            // Create new FileList
            const dt = new DataTransfer();
            files.forEach(file => dt.items.add(file));
            document.getElementById('batchFileInput').files = dt.files;
            this.handleBatchFileSelect({ target: { files: dt.files } });
        }
    }

    handleSingleFileSelect(e) {
        const file = e.target.files[0];
        const analyzeBtn = document.getElementById('analyzeSingleBtn');
        
        if (file && file.name.toLowerCase().endsWith('.apk')) {
            analyzeBtn.disabled = false;
            this.updateUploadAreaText('singleUploadArea', `Selected: ${file.name}`);
        } else {
            analyzeBtn.disabled = true;
            this.showError('Please select a valid APK file');
        }
    }

    handleBatchFileSelect(e) {
        const files = Array.from(e.target.files);
        const analyzeBtn = document.getElementById('analyzeBatchBtn');
        
        const apkFiles = files.filter(f => f.name.toLowerCase().endsWith('.apk'));
        
        if (apkFiles.length > 0) {
            analyzeBtn.disabled = false;
            this.updateUploadAreaText('batchUploadArea', 
                `Selected: ${apkFiles.length} APK file(s)`);
            this.displayFileList('batchUploadArea', apkFiles);
        } else {
            analyzeBtn.disabled = true;
            this.showError('Please select valid APK files');
        }
    }

    updateUploadAreaText(areaId, text) {
        const area = document.getElementById(areaId);
        const p = area.querySelector('p');
        if (p) {
            p.textContent = text;
        }
    }

    displayFileList(areaId, files) {
        const area = document.getElementById(areaId);
        
        // Remove existing file list
        const existingList = area.querySelector('.file-list');
        if (existingList) {
            existingList.remove();
        }
        
        // Create new file list
        const fileList = document.createElement('div');
        fileList.className = 'file-list mt-3';
        
        files.forEach(file => {
            const fileItem = document.createElement('div');
            fileItem.className = 'file-item';
            fileItem.innerHTML = `
                <span class="file-name">${file.name}</span>
                <span class="file-size">${this.formatFileSize(file.size)}</span>
            `;
            fileList.appendChild(fileItem);
        });
        
        area.appendChild(fileList);
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    async analyzeSingleFile() {
        const fileInput = document.getElementById('singleFileInput');
        const file = fileInput.files[0];
        
        if (!file) {
            this.showError('No file selected');
            return;
        }

        this.showLoading(true);
        
        try {
            const formData = new FormData();
            formData.append('apk_file', file);
            
            const response = await fetch('/api/detect', {
                method: 'POST',
                body: formData
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.currentResults = { type: 'single', data: result.result };
                this.displaySingleResult(result.result);
            } else {
                this.showError(result.error || 'Analysis failed');
            }
        } catch (error) {
            this.showError('Network error: ' + error.message);
                } finally {
            this.showLoading(false);
        }
    }

    async analyzeBatchFiles() {
        const fileInput = document.getElementById('batchFileInput');
        const files = Array.from(fileInput.files);
        
        if (files.length === 0) {
            this.showError('No files selected');
            return;
        }

        this.showLoading(true, `Analyzing ${files.length} files...`);
        
        try {
            const formData = new FormData();
            files.forEach(file => {
                formData.append('apk_files', file);
            });
            
            const response = await fetch('/api/batch-detect', {
                method: 'POST',
                body: formData
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.currentResults = { type: 'batch', data: result.result };
                this.displayBatchResults(result.result);
            } else {
                this.showError(result.error || 'Batch analysis failed');
            }
        } catch (error) {
            this.showError('Network error: ' + error.message);
        } finally {
            this.showLoading(false);
        }
    }

    displaySingleResult(result) {
        const resultsSection = document.getElementById('resultsSection');
        const resultsContent = document.getElementById('resultsContent');
        
        const riskClass = this.getRiskClass(result.risk_level);
        const confidenceClass = this.getConfidenceClass(result.confidence);
        
        resultsContent.innerHTML = `
            <div class="result-item ${result.is_fake ? 'fake' : 'legitimate'} fade-in-up">
                <div class="row">
                    <div class="col-md-8">
                        <h5 class="mb-3">
                            <i class="fas fa-mobile-alt me-2"></i>
                            ${result.filename || 'APK Analysis'}
                        </h5>
                        
                        <div class="mb-3">
                            <strong>Package:</strong> ${result.package_name || 'Unknown'}
                        </div>
                        
                        <div class="mb-3">
                            <strong>Detection Result:</strong>
                            <span class="badge ${result.is_fake ? 'bg-danger' : 'bg-success'} ms-2">
                                ${result.is_fake ? 'FAKE APK DETECTED' : 'APPEARS LEGITIMATE'}
                            </span>
                        </div>
                        
                        <div class="mb-3">
                            <strong>Confidence Level:</strong>
                            <div class="confidence-bar">
                                <div class="confidence-fill ${confidenceClass}" 
                                     style="width: ${result.confidence * 100}%"></div>
                            </div>
                            <small class="text-muted">${(result.confidence * 100).toFixed(1)}%</small>
                        </div>
                    </div>
                    
                    <div class="col-md-4">
                        <div class="risk-${result.risk_level.toLowerCase().replace('_', '-')} text-center">
                            <h4><i class="fas fa-exclamation-triangle me-2"></i>Risk Level</h4>
                            <h3>${result.risk_level.replace('_', ' ')}</h3>
                            <p class="mb-0">Fake Probability: ${(result.fake_probability * 100).toFixed(1)}%</p>
                        </div>
                    </div>
                </div>
                
                <!-- Recommendations -->
                <div class="mt-4">
                    <h6><i class="fas fa-lightbulb me-2"></i>Recommendations:</h6>
                    ${this.renderRecommendations(result.recommendations)}
                </div>
                
                <!-- Detection Details -->
                <div class="mt-4">
                    <h6><i class="fas fa-cogs me-2"></i>Detection Details:</h6>
                    ${this.renderDetectionDetails(result.detection_methods)}
                </div>
                
                <!-- APK Details -->
                <div class="mt-4">
                    <h6><i class="fas fa-info-circle me-2"></i>APK Information:</h6>
                    ${this.renderAPKDetails(result.apk_details)}
                </div>
            </div>
        `;
        
        resultsSection.style.display = 'block';
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }

    displayBatchResults(result) {
        const resultsSection = document.getElementById('resultsSection');
        const resultsContent = document.getElementById('resultsContent');
        
        let resultsHTML = `
            <div class="batch-summary fade-in-up">
                <div class="row text-center">
                    <div class="col-md-3">
                        <h3>${result.total_apks}</h3>
                        <p class="mb-0">Total APKs</p>
                    </div>
                    <div class="col-md-3">
                        <h3>${result.fake_apks_detected}</h3>
                        <p class="mb-0">Fake Detected</p>
                    </div>
                    <div class="col-md-3">
                        <h3>${result.legitimate_apks}</h3>
                        <p class="mb-0">Legitimate</p>
                    </div>
                    <div class="col-md-3">
                        <h3>${result.fake_percentage.toFixed(1)}%</h3>
                        <p class="mb-0">Fake Rate</p>
                    </div>
                </div>
            </div>
        `;
        
        // Individual results
        result.results.forEach((apkResult, index) => {
            const riskClass = this.getRiskClass(apkResult.risk_level);
            
            resultsHTML += `
                <div class="result-item ${apkResult.is_fake ? 'fake' : 'legitimate'} fade-in-up" 
                     style="animation-delay: ${index * 0.1}s">
                    <div class="row align-items-center">
                        <div class="col-md-6">
                            <h6 class="mb-2">
                                <i class="fas fa-mobile-alt me-2"></i>
                                ${apkResult.original_filename || apkResult.package_name || 'Unknown APK'}
                            </h6>
                            <div class="mb-2">
                                <span class="badge ${apkResult.is_fake ? 'bg-danger' : 'bg-success'}">
                                    ${apkResult.is_fake ? 'FAKE' : 'LEGITIMATE'}
                                </span>
                                <span class="badge bg-secondary ms-2">
                                    ${apkResult.risk_level.replace('_', ' ')}
                                </span>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <small class="text-muted">Confidence</small>
                            <div class="confidence-bar">
                                <div class="confidence-fill ${this.getConfidenceClass(apkResult.confidence)}" 
                                     style="width: ${apkResult.confidence * 100}%"></div>
                            </div>
                            <small>${(apkResult.confidence * 100).toFixed(1)}%</small>
                        </div>
                        <div class="col-md-3 text-end">
                            <button class="btn btn-sm btn-outline-primary" 
                                    onclick="detector.showDetailedResult(${index})">
                                <i class="fas fa-eye me-1"></i>
                                View Details
                            </button>
                        </div>
                    </div>
                </div>
            `;
        });
        
        resultsContent.innerHTML = resultsHTML;
        resultsSection.style.display = 'block';
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }

    showDetailedResult(index) {
        if (!this.currentResults || this.currentResults.type !== 'batch') return;
        
        const result = this.currentResults.data.results[index];
        
        // Create modal for detailed view
        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.innerHTML = `
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">
                            <i class="fas fa-mobile-alt me-2"></i>
                            Detailed Analysis: ${result.original_filename || result.package_name}
                        </h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="row">
                            <div class="col-md-8">
                                <div class="mb-3">
                                    <strong>Detection Result:</strong>
                                    <span class="badge ${result.is_fake ? 'bg-danger' : 'bg-success'} ms-2">
                                        ${result.is_fake ? 'FAKE APK DETECTED' : 'APPEARS LEGITIMATE'}
                                    </span>
                                </div>
                                
                                <div class="mb-3">
                                    <strong>Confidence Level:</strong>
                                    <div class="confidence-bar">
                                        <div class="confidence-fill ${this.getConfidenceClass(result.confidence)}" 
                                             style="width: ${result.confidence * 100}%"></div>
                                    </div>
                                    <small class="text-muted">${(result.confidence * 100).toFixed(1)}%</small>
                                </div>
                            </div>
                            
                            <div class="col-md-4">
                                <div class="risk-${result.risk_level.toLowerCase().replace('_', '-')} text-center">
                                    <h5>Risk Level</h5>
                                    <h4>${result.risk_level.replace('_', ' ')}</h4>
                                </div>
                            </div>
                        </div>
                        
                        <div class="mt-4">
                            <h6><i class="fas fa-lightbulb me-2"></i>Recommendations:</h6>
                            ${this.renderRecommendations(result.recommendations)}
                        </div>
                        
                        <div class="mt-4">
                            <h6><i class="fas fa-cogs me-2"></i>Detection Details:</h6>
                            ${this.renderDetectionDetails(result.detection_methods)}
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        const bsModal = new bootstrap.Modal(modal);
        bsModal.show();
        
        // Remove modal from DOM when hidden
        modal.addEventListener('hidden.bs.modal', () => {
            document.body.removeChild(modal);
        });
    }

    renderRecommendations(recommendations) {
        if (!recommendations || recommendations.length === 0) {
            return '<p class="text-muted">No specific recommendations available.</p>';
        }
        
        return recommendations.map(rec => {
            let recClass = 'info';
            if (rec.includes('⚠️') || rec.includes('DO NOT')) recClass = 'danger';
            else if (rec.includes('⚠️')) recClass = 'warning';
            else if (rec.includes('✅')) recClass = 'success';
            
            return `<div class="recommendation ${recClass}">${rec}</div>`;
        }).join('');
    }

    renderDetectionDetails(methods) {
        if (!methods) return '<p class="text-muted">No detection details available.</p>';
        
        let html = '<div class="row">';
        
        // Signature Analysis
        if (methods.signature_analysis) {
            const sig = methods.signature_analysis;
            html += `
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h6 class="mb-0"><i class="fas fa-signature me-2"></i>Signature Analysis</h6>
                        </div>
                        <div class="card-body">
                            <p><strong>Confidence:</strong> ${(sig.confidence * 100).toFixed(1)}%</p>
                            <p><strong>Fake Probability:</strong> ${(sig.fake_probability * 100).toFixed(1)}%</p>
                            ${sig.matched_bank ? `<p><strong>Matched Bank:</strong> ${sig.matched_bank}</p>` : ''}
                            ${sig.suspicious_indicators && sig.suspicious_indicators.length > 0 ? 
                                `<p><strong>Suspicious Indicators:</strong> ${sig.suspicious_indicators.join(', ')}</p>` : ''}
                        </div>
                    </div>
                </div>
            `;
        }
        
        // ML Analysis
        if (methods.ml_analysis) {
            const ml = methods.ml_analysis;
            html += `
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h6 class="mb-0"><i class="fas fa-brain me-2"></i>ML Analysis</h6>
                        </div>
                        <div class="card-body">
                            <p><strong>Model Available:</strong> ${ml.model_available ? 'Yes' : 'No'}</p>
                            ${ml.model_available ? `
                                <p><strong>Confidence:</strong> ${(ml.confidence * 100).toFixed(1)}%</p>
                                <p><strong>Risk Level:</strong> ${ml.risk_level}</p>
                                <p><strong>Prediction:</strong> ${ml.is_fake ? 'Fake' : 'Legitimate'}</p>
                            ` : '<p class="text-muted">ML model not available</p>'}
                        </div>
                    </div>
                </div>
            `;
        }
        
        html += '</div>';
        return html;
    }

    renderAPKDetails(details) {
        if (!details) return '<p class="text-muted">No APK details available.</p>';
        
        return `
            <div class="row">
                <div class="col-md-6">
                    <p><strong>File Size:</strong> ${this.formatFileSize(details.file_size || 0)}</p>
                    <p><strong>Permissions Count:</strong> ${details.permissions_count || 0}</p>
                </div>
                <div class="col-md-6">
                    <p><strong>Activities Count:</strong> ${details.activities_count || 0}</p>
                    <p><strong>Has Certificate:</strong> ${details.has_certificate ? 'Yes' : 'No'}</p>
                </div>
                ${details.md5_hash ? `
                    <div class="col-12">
                        <p><strong>MD5 Hash:</strong> <code>${details.md5_hash}</code></p>
                    </div>
                ` : ''}
            </div>
        `;
    }

    getRiskClass(riskLevel) {
        const level = riskLevel.toLowerCase().replace('_', '-');
        return `risk-${level}`;
    }

    getConfidenceClass(confidence) {
        if (confidence >= 0.7) return 'confidence-high';
        if (confidence >= 0.4) return 'confidence-medium';
        return 'confidence-low';
    }

    showLoading(show, message = 'Analyzing APK...') {
        const loadingIndicator = document.getElementById('loadingIndicator');
        const resultsSection = document.getElementById('resultsSection');
        
        if (show) {
            loadingIndicator.style.display = 'block';
            loadingIndicator.querySelector('h5').textContent = message;
            resultsSection.style.display = 'none';
        } else {
            loadingIndicator.style.display = 'none';
        }
    }

    showError(message) {
        // Create toast notification
        const toast = document.createElement('div');
        toast.className = 'toast align-items-center text-white bg-danger border-0';
        toast.setAttribute('role', 'alert');
        toast.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">
                    <i class="fas fa-exclamation-circle me-2"></i>
                    ${message}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" 
                        data-bs-dismiss="toast"></button>
            </div>
        `;
        
        // Add to page
        let toastContainer = document.querySelector('.toast-container');
        if (!toastContainer) {
            toastContainer = document.createElement('div');
            toastContainer.className = 'toast-container position-fixed top-0 end-0 p-3';
            document.body.appendChild(toastContainer);
        }
        
        toastContainer.appendChild(toast);
        
        // Show toast
        const bsToast = new bootstrap.Toast(toast);
        bsToast.show();
        
        // Remove from DOM after hiding
        toast.addEventListener('hidden.bs.toast', () => {
            toastContainer.removeChild(toast);
        });
    }

    async loadStatistics() {
        try {
            const response = await fetch('/api/stats');
            const stats = await response.json();
            
            document.getElementById('totalDetections').textContent = stats.total_detections || '-';
            document.getElementById('fakeDetected').textContent = stats.fake_apks_detected || '-';
            document.getElementById('detectionRate').textContent = 
                stats.detection_rate ? `${stats.detection_rate}%` : '-';
        } catch (error) {
            console.error('Failed to load statistics:', error);
        }
    }

    downloadResults() {
        if (!this.currentResults) {
            this.showError('No results to download');
            return;
        }
        
        const data = JSON.stringify(this.currentResults.data, null, 2);
        const blob = new Blob([data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = `apk_detection_results_${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        
        URL.revokeObjectURL(url);
    }
}

// Initialize the detector when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.detector = new APKDetector();
});

// Global function for downloading results
function downloadResults() {
    if (window.detector) {
        window.detector.downloadResults();
    }
}

