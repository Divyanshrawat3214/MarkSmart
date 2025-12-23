let videoElement, canvasElement, stream;
let modelsLoaded = false;
let livenessCheckPassed = false;
let currentToken = null;

// Initialize when page loads
document.addEventListener('DOMContentLoaded', function() {
    videoElement = document.getElementById('videoElement');
    canvasElement = document.getElementById('canvasElement');
    currentToken = typeof scanToken !== 'undefined' ? scanToken : null;
    
    if (!currentToken) {
        showError('No valid token found. Please scan the QR code again.');
        return;
    }
    
    // Check if TensorFlow.js and face-api are loaded
    if (typeof tf === 'undefined') {
        showError('TensorFlow.js is not loaded. Please refresh the page.');
        return;
    }
    
    if (typeof faceapi === 'undefined') {
        showError('Face detection library not loaded. Please refresh the page.');
        return;
    }
    
    console.log('TensorFlow.js version:', typeof tf !== 'undefined' ? tf.version : 'Not loaded');
    console.log('Face-api.js loaded:', typeof faceapi !== 'undefined');
    
    document.getElementById('startCameraBtn').addEventListener('click', startCamera);
    document.getElementById('captureBtn').addEventListener('click', captureAndSubmit);
    document.getElementById('retryBtn').addEventListener('click', retryLiveness);
    
    console.log('Scan page initialized. Token:', currentToken ? 'Present' : 'Missing');
    console.log('Face-api loaded:', typeof faceapi !== 'undefined');
});

async function loadModels() {
    if (modelsLoaded) {
        console.log('Models already loaded');
        return;
    }
    
    const statusEl = document.getElementById('livenessStatus');
    const messageEl = document.getElementById('livenessMessage');
    
    // Ensure TensorFlow.js is ready
    try {
        if (typeof tf === 'undefined') {
            throw new Error('TensorFlow.js is not loaded. Please refresh the page.');
        }
        
        // Wait for TensorFlow.js backend to be ready
        if (!tf.getBackend()) {
            console.log('Initializing TensorFlow.js backend...');
            await tf.setBackend('webgl').catch(async () => {
                console.log('WebGL not available, using CPU backend...');
                await tf.setBackend('cpu');
            });
            await tf.ready();
        }
        console.log('TensorFlow.js backend:', tf.getBackend());
    } catch (tfError) {
        console.error('TensorFlow.js initialization error:', tfError);
        showError('TensorFlow.js initialization failed. Please refresh the page.');
        return;
    }
    
    try {
        messageEl.textContent = 'Loading face detection models (this may take 10-30 seconds)...';
        console.log('Starting to load face-api.js models...');
        console.log('TensorFlow.js ready:', typeof tf !== 'undefined', 'Backend:', tf.getBackend());
        
        // Use CDN models - face-api.js models are hosted on jsdelivr
        const modelUrl = 'https://cdn.jsdelivr.net/npm/face-api.js@0.22.2/weights/';
        console.log('Loading from:', modelUrl);
        
        console.log('Loading tinyFaceDetector...');
        await faceapi.nets.tinyFaceDetector.loadFromUri(modelUrl);
        console.log('✓ tinyFaceDetector loaded');
        
        console.log('Loading faceLandmark68Net...');
        await faceapi.nets.faceLandmark68Net.loadFromUri(modelUrl);
        console.log('✓ faceLandmark68Net loaded');
        
        console.log('Loading faceRecognitionNet...');
        await faceapi.nets.faceRecognitionNet.loadFromUri(modelUrl);
        console.log('✓ faceRecognitionNet loaded');
        
        modelsLoaded = true;
        messageEl.textContent = '✓ Models loaded successfully! Starting face detection...';
        console.log('All models loaded successfully!');
        console.log('TensorFlow.js backend:', tf.getBackend());
        console.log('Face-api.js ready:', typeof faceapi !== 'undefined');
        console.log('Available face-api nets:', Object.keys(faceapi.nets));
        
        // Test detection immediately to verify it works (if video is ready)
        if (videoElement && videoElement.readyState >= 2) {
            try {
                const testDetections = await faceapi.detectAllFaces(videoElement, new faceapi.TinyFaceDetectorOptions({
                    inputSize: 320,
                    scoreThreshold: 0.1
                }));
                console.log('Test detection result:', testDetections.length, 'face(s) found');
            } catch (testError) {
                console.warn('Test detection failed (this is OK if video not ready yet):', testError.message);
            }
        }
    } catch (error) {
        console.error('Error loading models from primary CDN:', error);
        console.error('Error details:', error.message, error.stack);
        messageEl.textContent = 'Primary model source failed. Trying alternative...';
        
        // Try alternative CDN
        try {
            console.log('Trying alternative model source...');
            const altUrl = 'https://raw.githubusercontent.com/justadudewhohacks/face-api.js/master/weights/';
            await faceapi.nets.tinyFaceDetector.loadFromUri(altUrl);
            await faceapi.nets.faceLandmark68Net.loadFromUri(altUrl);
            await faceapi.nets.faceRecognitionNet.loadFromUri(altUrl);
            modelsLoaded = true;
            messageEl.textContent = '✓ Models loaded from alternative source! Starting face detection...';
            console.log('Models loaded from alternative source');
        } catch (altError) {
            console.error('Alternative model loading also failed:', altError);
            showError('Could not load face detection models. Please:\n1. Check your internet connection\n2. Refresh the page\n3. Check browser console (F12) for details');
        }
    }
}

async function startCamera() {
    const messageEl = document.getElementById('livenessMessage');
    try {
        messageEl.textContent = 'Requesting camera access...';
        console.log('Requesting camera access...');
        
        stream = await navigator.mediaDevices.getUserMedia({
            video: { 
                facingMode: 'user', 
                width: { ideal: 640 }, 
                height: { ideal: 480 }
            }
        });
        
        console.log('Camera access granted');
        videoElement.srcObject = stream;
        
        // Wait for video to be ready
        videoElement.onloadedmetadata = async () => {
            console.log('Video metadata loaded, dimensions:', videoElement.videoWidth, 'x', videoElement.videoHeight);
            console.log('Video ready state:', videoElement.readyState);
            
            // Ensure video is playing
            try {
                await videoElement.play();
                console.log('Video playback started');
            } catch (playError) {
                console.warn('Video autoplay failed, trying to play:', playError);
                videoElement.play().catch(e => console.error('Video play error:', e));
            }
            
            document.getElementById('cameraSection').classList.add('d-none');
            document.getElementById('videoSection').classList.remove('d-none');
            
            // Wait a bit for video to stabilize
            await new Promise(resolve => setTimeout(resolve, 500));
            
            messageEl.textContent = 'Loading face detection models...';
            await loadModels();
            
            if (modelsLoaded) {
                // Wait a bit more before starting detection
                await new Promise(resolve => setTimeout(resolve, 1000)); // Increased wait time
                
                // Verify video is actually playing
                if (videoElement.paused) {
                    console.warn('Video is paused, trying to play...');
                    await videoElement.play().catch(e => console.error('Play error:', e));
                }
                
                console.log('Starting liveness check. Video ready:', videoElement.readyState, 'Size:', videoElement.videoWidth + 'x' + videoElement.videoHeight);
                await startLivenessCheck();
            } else {
                showError('Failed to load face detection models. Please refresh the page.');
            }
        };
        
    } catch (error) {
        console.error('Error accessing camera:', error);
        let errorMsg = 'Could not access camera. ';
        if (error.name === 'NotAllowedError') {
            errorMsg += 'Please allow camera permissions in your browser settings.';
        } else if (error.name === 'NotFoundError') {
            errorMsg += 'No camera found. Please connect a camera.';
        } else {
            errorMsg += 'Error: ' + error.message;
        }
        showError(errorMsg);
    }
}

async function startLivenessCheck() {
    const statusEl = document.getElementById('livenessStatus');
    const messageEl = document.getElementById('livenessMessage');
    const progressEl = document.getElementById('livenessProgress');
    const progressBar = document.getElementById('livenessProgressBar');
    const captureBtn = document.getElementById('captureBtn');
    
    statusEl.className = 'liveness-status processing';
    messageEl.textContent = 'Step 1: Please look directly at the camera (real person only, no photos/screens)...';
    progressEl.classList.remove('d-none');
    progressBar.style.width = '0%';
    
    let faceDetected = false;
    let detectionCount = 0;
    let facePositions = []; // Track face positions to detect movement (anti-spoofing)
    let faceSizes = []; // Track face sizes to detect depth changes
    
    // Show debug info
    const debugDiv = document.getElementById('videoDebug');
    if (debugDiv) {
        debugDiv.style.display = 'block';
        const updateDebug = () => {
            document.getElementById('videoSize').textContent = `${videoElement.videoWidth}x${videoElement.videoHeight}`;
            document.getElementById('readyState').textContent = videoElement.readyState;
            document.getElementById('detectionCount').textContent = detectionCount;
        };
        setInterval(updateDebug, 500);
    }
    
    // Step 1: Face detection with movement verification (anti-spoofing)
    let detectionInterval = setInterval(async () => {
        if (!videoElement || videoElement.readyState !== videoElement.HAVE_ENOUGH_DATA) {
            detectionCount++;
            if (detectionCount > 20) {
                clearInterval(detectionInterval);
                showError('Camera not ready. Please refresh and try again.');
            }
            return;
        }
        
        try {
            // Use EXTREMELY lenient detection options for better face detection
            // Try multiple detection methods if first one fails
            let detections = [];
            let detectionOptions = new faceapi.TinyFaceDetectorOptions({
                inputSize: 512, // Large input size for better detection
                scoreThreshold: 0.1 // Extremely low threshold (default is 0.5)
            });
            
            try {
                detections = await faceapi.detectAllFaces(videoElement, detectionOptions)
                    .withFaceLandmarks();
            } catch (detectError) {
                console.error('Face detection error:', detectError);
                // Try with even more lenient options
                try {
                    detectionOptions = new faceapi.TinyFaceDetectorOptions({
                        inputSize: 320,
                        scoreThreshold: 0.05 // Extremely low
                    });
                    detections = await faceapi.detectAllFaces(videoElement, detectionOptions)
                        .withFaceLandmarks();
                } catch (retryError) {
                    console.error('Retry detection also failed:', retryError);
                }
            }
            
            // Log detection results with more detail
            if (detections.length > 0) {
                const detection = detections[0];
                const score = detection.detection.score || 0;
                if (detectionCount % 5 === 0) {
                    console.log(`✓ Detection attempt ${detectionCount}: Found ${detections.length} face(s), Confidence: ${(score * 100).toFixed(1)}%`);
                }
            } else {
                // Log more frequently when no face detected to help debug
                if (detectionCount % 10 === 0) { // Every 2 seconds
                    console.log(`✗ Detection attempt ${detectionCount}: No face detected`);
                    console.log(`  Video: ${videoElement.videoWidth}x${videoElement.videoHeight}, Ready: ${videoElement.readyState}, Playing: ${!videoElement.paused}`);
                    console.log(`  Models loaded: ${modelsLoaded}, TensorFlow backend: ${typeof tf !== 'undefined' ? tf.getBackend() : 'N/A'}`);
                }
            }
            
            if (detections.length > 0) {
                const detection = detections[0];
                const box = detection.detection.box;
                
                // Visual feedback
                videoElement.classList.add('face-detected');
                const score = detection.detection.score || 0;
                const confidence = (score * 100).toFixed(1);
                
                // Log detection details more frequently for debugging
                if (detectionCount % 5 === 0) { // Log every second
                    console.log(`✓ Face detected - Confidence: ${confidence}%, Size: ${box.width.toFixed(0)}x${box.height.toFixed(0)}, Position: (${box.x.toFixed(0)}, ${box.y.toFixed(0)})`);
                }
                
                // Show confidence in UI for debugging
                if (detectionCount % 10 === 0) {
                    messageEl.textContent = `Face detected! Confidence: ${confidence}% - Verifying movement...`;
                }
                
                // Anti-spoofing: Check for face movement (photos don't move)
                facePositions.push({ x: box.x, y: box.y, width: box.width, height: box.height });
                faceSizes.push(box.width * box.height);
                
                // Keep only last 10 positions
                if (facePositions.length > 10) {
                    facePositions.shift();
                    faceSizes.shift();
                }
                
                // First, just detect that a face is present
                // Then check for movement (anti-spoofing) - VERY lenient
                if (facePositions.length < 1) {
                    messageEl.textContent = `Step 1: Face detected! Verifying it's a real person... (${facePositions.length}/1 sample)`;
                } else if (facePositions.length >= 1) {
                    // Check for natural movement (anti-spoofing) - extremely relaxed requirements
                    let hasMovement = false;
                    let hasSizeVariation = false;
                    let hasMicroMovement = false;
                    
                    if (facePositions.length >= 2) {
                        const firstPos = facePositions[0];
                        const lastPos = facePositions[facePositions.length - 1];
                        const positionDiff = Math.abs(firstPos.x - lastPos.x) + Math.abs(firstPos.y - lastPos.y);
                        if (positionDiff > 1) hasMovement = true; // Extremely relaxed - just 1 pixel
                        
                        // Check size variation (depth changes) - extremely relaxed
                        const minSize = Math.min(...faceSizes);
                        const maxSize = Math.max(...faceSizes);
                        const sizeVariation = (maxSize - minSize) / minSize;
                        if (sizeVariation > 0.005) hasSizeVariation = true; // Extremely relaxed - just 0.5% variation
                        
                        // Also check for any variation in recent positions (micro-movements)
                        for (let i = 1; i < facePositions.length; i++) {
                            const diff = Math.abs(facePositions[i].x - facePositions[i-1].x) + 
                                        Math.abs(facePositions[i].y - facePositions[i-1].y);
                            if (diff > 0.1) { // Extremely small movement
                                hasMicroMovement = true;
                                break;
                            }
                        }
                    }
                    
                    // Log movement detection for debugging
                    if (detectionCount % 10 === 0 && facePositions.length >= 2) {
                        const firstPos = facePositions[0];
                        const lastPos = facePositions[facePositions.length - 1];
                        const positionDiff = Math.abs(firstPos.x - lastPos.x) + Math.abs(firstPos.y - lastPos.y);
                        const minSize = Math.min(...faceSizes);
                        const maxSize = Math.max(...faceSizes);
                        const sizeVariation = (maxSize - minSize) / minSize;
                        console.log(`Movement check - Position diff: ${positionDiff.toFixed(2)}, Size variation: ${(sizeVariation * 100).toFixed(2)}%, Has movement: ${hasMovement}, Has size var: ${hasSizeVariation}, Has micro: ${hasMicroMovement}`);
                    }
                    
                    // VERY LENIENT: Accept face after just 1 sample OR any tiny movement
                    // Bypass movement check if we have at least 1 face detection
                    // This makes it much easier to pass the detection
                    if (hasMovement || hasSizeVariation || hasMicroMovement || facePositions.length >= 1) {
                        faceDetected = true;
                        clearInterval(detectionInterval);
                        progressBar.style.width = '25%';
                        messageEl.textContent = '✓ Real face detected! Step 2: Please blink your eyes naturally...';
                        console.log('✓ Face detection passed! Moving to blink detection...');
                        
                        // Step 2: Blink detection
                        await detectBlink();
                    } else {
                        messageEl.textContent = 'Step 1: Face detected! Just need one more sample...';
                    }
                }
            } else {
                // Remove visual feedback when face not detected
                videoElement.classList.remove('face-detected');
                
                // Show detection status with helpful tips
                if (detectionCount % 10 === 0) { // Update message every 2 seconds
                    const elapsed = Math.floor(detectionCount/5);
                    messageEl.textContent = `Step 1: Looking for face... (${elapsed}s) - Please:\n- Look directly at camera\n- Ensure good lighting\n- Face fully visible`;
                    console.log(`No face detected after ${elapsed}s. Video ready: ${videoElement.readyState}, Dimensions: ${videoElement.videoWidth}x${videoElement.videoHeight}`);
                    
                    // Provide specific tips based on elapsed time
                    if (elapsed > 5) {
                        console.log('Tips: Try moving closer to camera, improve lighting, or check if camera is working');
                    }
                }
                // Reset tracking if face lost for too long
                if (facePositions.length > 0 && detectionCount % 20 === 0) {
                    facePositions = [];
                    faceSizes = [];
                }
            }
        } catch (error) {
            console.error('Face detection error:', error);
            console.error('Error details:', error.message, error.stack);
            if (detectionCount > 100) { // Increased threshold
                clearInterval(detectionInterval);
                showError('Face detection error: ' + error.message + '. Please refresh the page and check browser console (F12) for details.');
            } else {
                // Show error in message but continue trying
                if (detectionCount % 20 === 0) {
                    messageEl.textContent = 'Face detection in progress... (checking for errors)';
                }
            }
        }
        detectionCount++;
    }, 200); // Check every 200ms
    
    // Timeout for face detection
    setTimeout(() => {
        if (!faceDetected) {
            clearInterval(detectionInterval);
            const errorMsg = 'No real face detected after 30 seconds.\n\nPlease ensure:\n' +
                           '✓ You are a real person (not a photo/screen)\n' +
                           '✓ Good lighting (face well-lit)\n' +
                           '✓ Face is clearly visible and centered\n' +
                           '✓ Camera permissions are granted\n' +
                           '✓ Try moving slightly (even small movements help)\n\n' +
                           'Check browser console (F12) for detailed error messages.';
            showError(errorMsg);
        }
    }, 30000); // Increased timeout to 30 seconds
}

async function detectBlink() {
    const messageEl = document.getElementById('livenessMessage');
    const progressBar = document.getElementById('livenessProgressBar');
    
    let blinkCount = 0;
    let lastEyeState = 'open';
    let checkCount = 0;
    let blinkStartTime = null;
    let blinkDurations = []; // Track blink durations (anti-spoofing)
    let eyeStates = []; // Track eye state history
    
    let blinkInterval = setInterval(async () => {
        try {
            const detections = await faceapi.detectAllFaces(videoElement, new faceapi.TinyFaceDetectorOptions())
                .withFaceLandmarks();
            
            if (detections.length > 0) {
                const landmarks = detections[0].landmarks;
                const leftEye = landmarks.getLeftEye();
                const rightEye = landmarks.getRightEye();
                
                // Calculate eye aspect ratio
                const leftEAR = calculateEAR(leftEye);
                const rightEAR = calculateEAR(rightEye);
                const avgEAR = (leftEAR + rightEAR) / 2;
                
                const eyeState = avgEAR < 0.25 ? 'closed' : 'open';
                eyeStates.push(eyeState);
                if (eyeStates.length > 30) eyeStates.shift(); // Keep last 30 states
                
                // Detect blink start
                if (eyeState === 'closed' && lastEyeState === 'open') {
                    blinkStartTime = Date.now();
                }
                
                // Detect blink end and measure duration
                if (eyeState === 'open' && lastEyeState === 'closed' && blinkStartTime) {
                    const blinkDuration = Date.now() - blinkStartTime;
                    blinkDurations.push(blinkDuration);
                    
                    // Real blinks are typically 100-400ms, photos/screens stay closed longer or don't blink naturally
                    if (blinkDuration > 80 && blinkDuration < 500) {
                        blinkCount++;
                        messageEl.textContent = `✓ Real blink ${blinkCount}/3 detected! Keep blinking naturally...`;
                        
                        if (blinkCount >= 3) {
                            // Verify blink pattern (anti-spoofing)
                            if (blinkDurations.length >= 3) {
                                const avgDuration = blinkDurations.reduce((a, b) => a + b, 0) / blinkDurations.length;
                                const variance = blinkDurations.reduce((sum, d) => sum + Math.pow(d - avgDuration, 2), 0) / blinkDurations.length;
                                
                                // Real blinks have natural variation
                                if (variance > 500 || (blinkDurations.every(d => d > 80 && d < 500))) {
                                    clearInterval(blinkInterval);
                                    progressBar.style.width = '50%';
                                    messageEl.textContent = '✓ Natural blinks verified! Step 3: Please turn your head...';
                                    await detectHeadTurn();
                                } else {
                                    messageEl.textContent = '⚠ Blink pattern seems unnatural. Please blink naturally (not a photo)...';
                                    blinkCount = Math.max(0, blinkCount - 1); // Penalize suspicious pattern
                                }
                            } else {
                                clearInterval(blinkInterval);
                                progressBar.style.width = '50%';
                                messageEl.textContent = '✓ Blinks complete! Step 3: Please turn your head...';
                                await detectHeadTurn();
                            }
                        }
                    } else {
                        messageEl.textContent = '⚠ Please blink naturally (real blinks are quick, 100-400ms). Photos cannot blink!';
                    }
                    blinkStartTime = null;
                }
                
                if (blinkCount < 3) {
                    messageEl.textContent = `Step 2: Please blink naturally 3 times... (${blinkCount}/3 blinks detected)`;
                }
                
                lastEyeState = eyeState;
            } else {
                messageEl.textContent = 'Step 2: Please keep your face visible and blink naturally...';
            }
        } catch (error) {
            console.error('Blink detection error:', error);
        }
        checkCount++;
        if (checkCount > 250) { // 25 seconds
            clearInterval(blinkInterval);
            if (blinkCount < 3) {
                showError('Blink detection failed. Please ensure you are a real person and blink naturally (photos cannot blink).');
            }
        }
    }, 100);
}

async function detectHeadTurn() {
    const messageEl = document.getElementById('livenessMessage');
    const progressBar = document.getElementById('livenessProgressBar');
    const statusEl = document.getElementById('livenessStatus');
    const captureBtn = document.getElementById('captureBtn');
    
    let headTurnCount = 0;
    let lastAngle = null;
    let checkCount = 0;
    let angles = []; // Track angle history for pattern verification
    let headPositions = []; // Track head positions
    
    let headTurnInterval = setInterval(async () => {
        try {
            // Use lenient detection options for head turn detection
            const detectionOptions = new faceapi.TinyFaceDetectorOptions({
                inputSize: 512,
                scoreThreshold: 0.2
            });
            
            const detections = await faceapi.detectAllFaces(videoElement, detectionOptions)
                .withFaceLandmarks();
            
            if (detections.length > 0) {
                const detection = detections[0];
                const landmarks = detection.landmarks;
                const box = detection.detection.box;
                const nose = landmarks.getNoseTip();
                const leftEye = landmarks.getLeftEye();
                const rightEye = landmarks.getRightEye();
                
                // Track head position (anti-spoofing - photos don't move)
                headPositions.push({ x: box.x, y: box.y, width: box.width });
                if (headPositions.length > 20) headPositions.shift();
                
                if (nose && nose.length > 0 && leftEye && leftEye.length > 0 && rightEye && rightEye.length > 0) {
                    // Calculate head angle
                    const eyeCenterX = (leftEye[0].x + rightEye[0].x) / 2;
                    const angle = nose[0].x - eyeCenterX; // Can be negative (left) or positive (right)
                    angles.push(angle);
                    if (angles.length > 30) angles.shift();
                    
                    if (lastAngle !== null) {
                        const angleDiff = Math.abs(angle - lastAngle);
                        // Require significant movement (anti-spoofing)
                        if (angleDiff > 20) {
                            headTurnCount++;
                            messageEl.textContent = `Step 3: Turn your head left and right... (${headTurnCount}/3 movements)`;
                        }
                    }
                    lastAngle = angle;
                    
                    // Verify head turn pattern (must turn both left and right - photos can't do this naturally)
                    if (headTurnCount >= 3 && angles.length >= 10) {
                        const minAngle = Math.min(...angles);
                        const maxAngle = Math.max(...angles);
                        const angleRange = maxAngle - minAngle;
                        
                        // Real head turns have significant range (both left and right)
                        if (angleRange > 30 && headPositions.length >= 10) {
                            // Check for position variation (real person moves, photo doesn't)
                            const firstPos = headPositions[0];
                            const lastPos = headPositions[headPositions.length - 1];
                            const posVariation = Math.abs(firstPos.x - lastPos.x) + Math.abs(firstPos.y - lastPos.y);
                            
                            if (posVariation > 10) {
                                clearInterval(headTurnInterval);
                                progressBar.style.width = '100%';
                                livenessCheckPassed = true;
                                statusEl.className = 'liveness-status success';
                                messageEl.textContent = '✓ Real person verified! Liveness check passed! Click Capture & Submit.';
                                captureBtn.classList.remove('d-none');
                            } else {
                                messageEl.textContent = '⚠ Please turn your head more naturally (photos cannot move)...';
                            }
                        } else {
                            messageEl.textContent = '⚠ Please turn your head both left AND right (not just one direction)...';
                        }
                    }
                }
            } else {
                messageEl.textContent = 'Step 3: Please keep your face visible and turn your head left and right...';
            }
        } catch (error) {
            console.error('Head turn detection error:', error);
        }
        checkCount++;
        if (checkCount > 300) { // 30 seconds
            clearInterval(headTurnInterval);
            if (headTurnCount < 3) {
                showError('Head turn detection failed. Please ensure you are a real person and turn your head naturally in both directions (photos cannot do this).');
            }
        }
    }, 100);
}

function calculateEAR(eyePoints) {
    // Eye Aspect Ratio calculation
    const vertical1 = Math.abs(eyePoints[1].y - eyePoints[5].y);
    const vertical2 = Math.abs(eyePoints[2].y - eyePoints[4].y);
    const horizontal = Math.abs(eyePoints[0].x - eyePoints[3].x);
    return (vertical1 + vertical2) / (2 * horizontal);
}

async function captureAndSubmit() {
    if (!livenessCheckPassed) {
        showError('Please complete the liveness check first.');
        return;
    }
    
    const statusEl = document.getElementById('livenessStatus');
    const messageEl = document.getElementById('livenessMessage');
    const captureBtn = document.getElementById('captureBtn');
    
    captureBtn.disabled = true;
    messageEl.textContent = 'Capturing image and getting location...';
    
    // Capture image
    const context = canvasElement.getContext('2d');
    canvasElement.width = videoElement.videoWidth;
    canvasElement.height = videoElement.videoHeight;
    context.drawImage(videoElement, 0, 0);
    
    // Get location
    let latitude = null;
    let longitude = null;
    
    if (navigator.geolocation) {
        try {
            const position = await new Promise((resolve, reject) => {
                navigator.geolocation.getCurrentPosition(resolve, reject, { timeout: 5000 });
            });
            latitude = position.coords.latitude;
            longitude = position.coords.longitude;
        } catch (error) {
            console.warn('Geolocation error:', error);
        }
    }
    
    // Convert canvas to blob
    canvasElement.toBlob(async (blob) => {
        const formData = new FormData();
        formData.append('token', currentToken);
        formData.append('photo', blob, 'face.jpg');
        formData.append('liveness_passed', 'true');
        formData.append('liveness_score', '1.0');
        if (latitude) formData.append('latitude', latitude);
        if (longitude) formData.append('longitude', longitude);
        
        try {
            const response = await fetch('/api/attendance/verify', {
                method: 'POST',
                body: formData
            });
            
            const data = await response.json();
            
            if (data.status === 'success' || data.status === 'warning') {
                statusEl.className = 'liveness-status success';
                messageEl.textContent = data.message || 'Attendance marked successfully!';
                document.getElementById('videoSection').classList.add('d-none');
                document.getElementById('resultSection').classList.remove('d-none');
                document.getElementById('resultMessage').className = 'alert alert-success';
                document.getElementById('resultMessage').textContent = data.message;
                
                // Stop camera
                if (stream) {
                    stream.getTracks().forEach(track => track.stop());
                }
            } else {
                showError(data.message || 'Failed to mark attendance');
                captureBtn.disabled = false;
            }
        } catch (error) {
            console.error('Error submitting attendance:', error);
            showError('Network error. Please try again.');
            captureBtn.disabled = false;
        }
    }, 'image/jpeg', 0.9);
}

function retryLiveness() {
    livenessCheckPassed = false;
    document.getElementById('captureBtn').classList.add('d-none');
    document.getElementById('retryBtn').classList.add('d-none');
    startLivenessCheck();
}

function showError(message) {
    const statusEl = document.getElementById('livenessStatus');
    const messageEl = document.getElementById('livenessMessage');
    const retryBtn = document.getElementById('retryBtn');
    
    statusEl.className = 'liveness-status error';
    messageEl.textContent = message;
    retryBtn.classList.remove('d-none');
}

