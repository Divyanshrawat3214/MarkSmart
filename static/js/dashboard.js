// Dashboard JavaScript for QR generation and attendance management

document.addEventListener('DOMContentLoaded', function() {
    // QR Generation
    const generateQRBtn = document.getElementById('generateQRBtn');
    if (generateQRBtn) {
        generateQRBtn.addEventListener('click', generateQR);
    }
    
    const regenerateQRBtn = document.getElementById('regenerateQRBtn');
    if (regenerateQRBtn) {
        regenerateQRBtn.addEventListener('click', generateQR);
    }
    
    // Load data when tabs are shown
    const attendanceTab = document.getElementById('attendance-tab');
    if (attendanceTab) {
        attendanceTab.addEventListener('shown.bs.tab', function() {
            loadAttendanceData();
        });
    }
    
    const studentsTab = document.getElementById('students-tab');
    if (studentsTab) {
        studentsTab.addEventListener('shown.bs.tab', function() {
            loadStudentsData();
        });
    }
    
    const todayTab = document.getElementById('today-tab');
    if (todayTab) {
        todayTab.addEventListener('shown.bs.tab', function() {
            loadTodayAttendance();
        });
    }
    
    // Export button
    const exportBtn = document.getElementById('exportAttendanceBtn');
    if (exportBtn) {
        exportBtn.addEventListener('click', exportAttendance);
    }
    
    // Filter button
    const applyFiltersBtn = document.getElementById('applyFiltersBtn');
    if (applyFiltersBtn) {
        applyFiltersBtn.addEventListener('click', loadAttendanceData);
    }
});

let tokenExpiryInterval = null;

async function generateQR() {
    const btn = document.getElementById('generateQRBtn');
    const display = document.getElementById('qrDisplay');
    const qrImage = document.getElementById('qrImage');
    const downloadLink = document.getElementById('downloadQR');
    
    btn.disabled = true;
    btn.textContent = 'Generating...';
    
    try {
        // Get CSRF token from meta tag or form
        let csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
        if (!csrfToken) {
            // Try to get from any form on the page
            const form = document.querySelector('form');
            if (form) {
                const tokenInput = form.querySelector('input[name="csrf_token"]');
                if (tokenInput) csrfToken = tokenInput.value;
            }
        }
        
        // Use FormData to send CSRF token properly
        const formData = new FormData();
        if (csrfToken) {
            formData.append('csrf_token', csrfToken);
        }
        
        const response = await fetch('/generate_qr', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
            qrImage.src = data.qr_url;
            downloadLink.href = data.qr_url;
            display.classList.remove('d-none');
            
            // Start countdown
            startTokenCountdown(data.expires_in);
        } else {
            alert('Error generating QR code: ' + (data.message || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error generating QR code. Please try again.');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Generate Today\'s QR Code';
    }
}

function startTokenCountdown(seconds) {
    const expiryEl = document.getElementById('tokenExpiry');
    if (!expiryEl) return;
    
    if (tokenExpiryInterval) {
        clearInterval(tokenExpiryInterval);
    }
    
    let remaining = seconds;
    
    tokenExpiryInterval = setInterval(() => {
        const mins = Math.floor(remaining / 60);
        const secs = remaining % 60;
        expiryEl.textContent = `${mins}:${secs.toString().padStart(2, '0')}`;
        
        remaining--;
        if (remaining < 0) {
            clearInterval(tokenExpiryInterval);
            expiryEl.textContent = 'Expired';
        }
    }, 1000);
}

let attendanceTable = null;

async function loadAttendanceData() {
    const tbody = document.querySelector('#attendanceTable tbody');
    if (!tbody) return;
    
    // Get filter values
    const dateFrom = document.getElementById('filterDateFrom')?.value;
    const dateTo = document.getElementById('filterDateTo')?.value;
    const enrollNo = document.getElementById('filterEnrollNo')?.value;
    
    const params = new URLSearchParams();
    if (dateFrom) params.append('date_from', dateFrom);
    if (dateTo) params.append('date_to', dateTo);
    if (enrollNo) params.append('enroll_no', enrollNo);
    
    try {
        const response = await fetch(`/api/attendance?${params.toString()}`);
        const data = await response.json();
        
        if (data.status === 'success') {
            tbody.innerHTML = '';
            
            data.records.forEach((record, index) => {
                const row = document.createElement('tr');
                const location = (record.latitude && record.longitude) 
                    ? `${parseFloat(record.latitude).toFixed(4)}, ${parseFloat(record.longitude).toFixed(4)}`
                    : 'N/A';
                
                row.innerHTML = `
                    <td>${record.enroll_no || ''}</td>
                    <td>${record.name || ''}</td>
                    <td>${record.date || ''}</td>
                    <td>${record.time || ''}</td>
                    <td>${location}</td>
                    <td>${record.liveness_score || 'N/A'}</td>
                    <td>
                        <button class="btn btn-sm btn-danger" onclick="deleteAttendance(${index})">Delete</button>
                    </td>
                `;
                tbody.appendChild(row);
            });
            
            // Initialize DataTable if not already done
            if (!attendanceTable) {
                attendanceTable = $('#attendanceTable').DataTable({
                    order: [[2, 'desc']] // Sort by date descending
                });
            } else {
                attendanceTable.draw();
            }
        }
    } catch (error) {
        console.error('Error loading attendance:', error);
    }
}

async function deleteAttendance(index) {
    if (!confirm('Are you sure you want to delete this attendance record?')) {
        return;
    }
    
    try {
        const response = await fetch(`/api/attendance/delete/${index}`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
            loadAttendanceData();
        } else {
            alert('Error: ' + (data.message || 'Failed to delete'));
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error deleting record. Please try again.');
    }
}

function exportAttendance() {
    const dateFrom = document.getElementById('filterDateFrom')?.value;
    const dateTo = document.getElementById('filterDateTo')?.value;
    const enrollNo = document.getElementById('filterEnrollNo')?.value;
    
    const params = new URLSearchParams();
    if (dateFrom) params.append('date_from', dateFrom);
    if (dateTo) params.append('date_to', dateTo);
    if (enrollNo) params.append('enroll_no', enrollNo);
    
    window.location.href = `/api/attendance/export?${params.toString()}`;
}

async function loadTodayAttendance() {
    const tbody = document.querySelector('#todayTable tbody');
    const countEl = document.getElementById('todayCount');
    
    if (!tbody) return;
    
    try {
        const response = await fetch('/api/attendance/today');
        const data = await response.json();
        
        if (data.status === 'success') {
            if (countEl) {
                countEl.textContent = data.count || 0;
            }
            
            tbody.innerHTML = '';
            
            data.records.forEach(record => {
                const row = document.createElement('tr');
                const location = (record.latitude && record.longitude) 
                    ? `${parseFloat(record.latitude).toFixed(4)}, ${parseFloat(record.longitude).toFixed(4)}`
                    : 'N/A';
                
                row.innerHTML = `
                    <td>${record.enroll_no || ''}</td>
                    <td>${record.name || ''}</td>
                    <td>${record.time || ''}</td>
                    <td>${location}</td>
                    <td>${record.liveness_score || 'N/A'}</td>
                `;
                tbody.appendChild(row);
            });
        }
    } catch (error) {
        console.error('Error loading today\'s attendance:', error);
    }
}
