// Students management JavaScript

let studentsTable = null;

document.addEventListener('DOMContentLoaded', function() {
    // Add student form
    const addStudentForm = document.getElementById('addStudentForm');
    if (addStudentForm) {
        addStudentForm.addEventListener('submit', handleAddStudent);
    }
    
    // Bulk upload form
    const bulkUploadForm = document.getElementById('bulkUploadForm');
    if (bulkUploadForm) {
        bulkUploadForm.addEventListener('submit', handleBulkUpload);
    }
    
    // Load students when students tab is shown (handled in dashboard.js)
    // But also load on page load if we're on students tab
    const studentsTab = document.getElementById('students-tab');
    if (studentsTab && studentsTab.classList.contains('active')) {
        loadStudentsData();
    }
});

async function loadStudentsData() {
    const tbody = document.querySelector('#studentsTable tbody');
    if (!tbody) return;
    
    try {
        const response = await fetch('/api/students');
        const data = await response.json();
        
        if (data.status === 'success') {
            tbody.innerHTML = '';
            
            data.students.forEach(student => {
                const row = document.createElement('tr');
                const photoUrl = student.photo_filename 
                    ? `/uploads/${student.photo_filename}` 
                    : '/static/no-image.png';
                
                row.innerHTML = `
                    <td>${student.enroll_no || ''}</td>
                    <td>${student.name || ''}</td>
                    <td>${student.class || ''}</td>
                    <td>
                        ${student.photo_filename ? 
                            `<img src="${photoUrl}" alt="Photo" style="max-width: 50px; max-height: 50px;">` : 
                            'No photo'}
                    </td>
                    <td>
                        <button class="btn btn-sm btn-primary" onclick="editStudent('${student.enroll_no}')">Edit</button>
                        <button class="btn btn-sm btn-danger" onclick="deleteStudent('${student.enroll_no}')">Delete</button>
                    </td>
                `;
                tbody.appendChild(row);
            });
            
            // Initialize DataTable if not already done
            if (!studentsTable) {
                studentsTable = $('#studentsTable').DataTable();
            } else {
                studentsTable.draw();
            }
        }
    } catch (error) {
        console.error('Error loading students:', error);
    }
}

async function handleAddStudent(e) {
    e.preventDefault();
    
    const formData = new FormData(e.target);
    const submitBtn = e.target.querySelector('button[type="submit"]');
    
    submitBtn.disabled = true;
    submitBtn.textContent = 'Adding...';
    
    try {
        const response = await fetch('/api/students/add', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
            alert('Student added successfully!');
            e.target.reset();
            bootstrap.Modal.getInstance(document.getElementById('addStudentModal')).hide();
            loadStudentsData();
        } else {
            alert('Error: ' + (data.message || 'Failed to add student'));
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error adding student. Please try again.');
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Add Student';
    }
}

async function editStudent(enrollNo) {
    // Load student data and show edit modal
    try {
        const response = await fetch('/api/students');
        const data = await response.json();
        
        if (data.status === 'success') {
            const student = data.students.find(s => s.enroll_no === enrollNo);
            if (student) {
                // Create/edit modal dynamically or use existing
                const editModal = document.createElement('div');
                editModal.className = 'modal fade';
                editModal.innerHTML = `
                    <div class="modal-dialog">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title">Edit Student</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                            </div>
                            <form id="editStudentForm">
                                <div class="modal-body">
                                    <div class="mb-3">
                                        <label class="form-label">Enrollment Number</label>
                                        <input type="text" class="form-control" name="enroll_no" value="${student.enroll_no}" readonly>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">Name *</label>
                                        <input type="text" class="form-control" name="name" value="${student.name || ''}" required>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">Class *</label>
                                        <input type="text" class="form-control" name="class" value="${student.class || ''}" required>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">Photo (leave empty to keep current)</label>
                                        <input type="file" class="form-control" name="photo" accept="image/*">
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">Metadata</label>
                                        <textarea class="form-control" name="metadata" rows="2">${student.metadata || ''}</textarea>
                                    </div>
                                </div>
                                <div class="modal-footer">
                                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                    <button type="submit" class="btn btn-primary">Update Student</button>
                                </div>
                            </form>
                        </div>
                    </div>
                `;
                
                document.body.appendChild(editModal);
                const bsModal = new bootstrap.Modal(editModal);
                bsModal.show();
                
                editModal.querySelector('#editStudentForm').addEventListener('submit', async (e) => {
                    e.preventDefault();
                    await handleEditStudent(enrollNo, new FormData(e.target), bsModal);
                });
                
                editModal.addEventListener('hidden.bs.modal', () => {
                    editModal.remove();
                });
            }
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error loading student data.');
    }
}

async function handleEditStudent(enrollNo, formData, modal) {
    const submitBtn = modal._element.querySelector('button[type="submit"]');
    
    submitBtn.disabled = true;
    submitBtn.textContent = 'Updating...';
    
    try {
        const response = await fetch(`/api/students/edit/${enrollNo}`, {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
            alert('Student updated successfully!');
            modal.hide();
            loadStudentsData();
        } else {
            alert('Error: ' + (data.message || 'Failed to update student'));
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error updating student. Please try again.');
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Update Student';
    }
}

async function deleteStudent(enrollNo) {
    if (!confirm(`Are you sure you want to delete student ${enrollNo}?`)) {
        return;
    }
    
    try {
        const response = await fetch(`/api/students/delete/${enrollNo}`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
            alert('Student deleted successfully!');
            loadStudentsData();
        } else {
            alert('Error: ' + (data.message || 'Failed to delete student'));
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error deleting student. Please try again.');
    }
}

async function handleBulkUpload(e) {
    e.preventDefault();
    
    const formData = new FormData(e.target);
    const submitBtn = e.target.querySelector('button[type="submit"]');
    
    submitBtn.disabled = true;
    submitBtn.textContent = 'Uploading...';
    
    try {
        const response = await fetch('/api/students/bulk_upload', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
            alert(`${data.message}\nSuccess: ${data.success_count}, Errors: ${data.error_count}`);
            if (data.errors && data.errors.length > 0) {
                console.log('Errors:', data.errors);
            }
            e.target.reset();
            bootstrap.Modal.getInstance(document.getElementById('bulkUploadModal')).hide();
            loadStudentsData();
        } else {
            alert('Error: ' + (data.message || 'Failed to upload'));
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error uploading file. Please try again.');
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Upload';
    }
}

