let currentEditUserId = null;
let allRoles = [];
let allPermissions = [];
let requirePasswordChange = false; // set by loadCurrentUser if needed
let currentUserEmail = '';

// Reset Password Modal element references (needed early for DOMContentLoaded)
const resetPasswordBtn = document.getElementById('reset-password-btn');
const resetPasswordModal = document.getElementById('reset-password-modal');
const cancelResetBtn = document.getElementById('cancel-reset');
const resetPasswordForm = document.getElementById('reset-password-form');
const newPasswordInput = document.getElementById('new-password');
const confirmPasswordInput = document.getElementById('confirm-password');
const passwordError = document.getElementById('password-error');
const passwordSuccess = document.getElementById('password-success');

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
  try {
    await loadCurrentUser();
    await loadRoles();
    await loadUsers();

    // Check if forced password change required after user is loaded
    if (requirePasswordChange) {
      resetPasswordModal.classList.remove('hidden');
      cancelResetBtn.style.display = 'none';
    }
  } catch (err) {
    // Authentication failed, redirect handled in loadCurrentUser
  }
});

// Tab switching
document.querySelectorAll('.tab-button').forEach((btn) => {
  btn.addEventListener('click', () => {
    const tabName = btn.dataset.tab;
    document.querySelectorAll('.tab-button').forEach((b) => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach((t) => t.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(tabName).classList.add('active');

    if (tabName === 'roles-tab') {
      loadRolesTab();
    }
  });
});

// Load current user
async function loadCurrentUser() {
  try {
    const response = await fetch('/api/auth/me', { credentials: 'same-origin' });
    if (!response.ok) throw new Error('Not authenticated');

    const data = await response.json();
    document.getElementById('current-user').textContent = data.user.username;
    currentUserEmail = data.user.email || '';
    // update hidden username display if exists
    const menuName = document.getElementById('current-user');
    if (menuName) menuName.textContent = data.user.username;

    if (data.user.forcePasswordChange) {
      requirePasswordChange = true;
    }
  } catch (err) {
    window.location.href = '/';
    throw err; // Re-throw to stop initialization
  }
}

// User menu toggle & logout
const userMenuBtn = document.getElementById('user-menu-btn');
const userMenu = document.getElementById('user-menu');
userMenuBtn.addEventListener('click', (e) => {
  e.stopPropagation();
  userMenu.classList.toggle('hidden');
});
document.addEventListener('click', (e) => {
  if (!userMenuBtn.contains(e.target) && !userMenu.contains(e.target)) {
    userMenu.classList.add('hidden');
  }
});
document.getElementById('menu-logout').addEventListener('click', async () => {
  try {
    await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' });
    window.location.href = '/';
  } catch (err) {
    console.error('Logout error:', err);
  }
});

// Reset Password Modal functionality
// Open modal
resetPasswordBtn.addEventListener('click', () => {
  resetPasswordModal.classList.remove('hidden');
  newPasswordInput.focus();
});

// Close modal
function closeResetPasswordModal() {
  if (requirePasswordChange) {
    return; // cannot close while forced
  }
  resetPasswordModal.classList.add('hidden');
  resetPasswordForm.reset();
  passwordError.classList.add('hidden');
  passwordSuccess.classList.add('hidden');
  resetPasswordForm.style.display = 'block';
}

cancelResetBtn.addEventListener('click', closeResetPasswordModal);

// Close modal when clicking outside
resetPasswordModal.addEventListener('click', (e) => {
  if (e.target === resetPasswordModal) {
    closeResetPasswordModal();
  }
});

// Handle form submission
resetPasswordForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  const newPassword = newPasswordInput.value.trim();
  const confirmPassword = confirmPasswordInput.value.trim();

  // Validate passwords match
  if (newPassword !== confirmPassword) {
    passwordError.textContent = 'Passwords do not match';
    passwordError.classList.remove('hidden');
    return;
  }

  // Validate password length
  if (newPassword.length < 6) {
    passwordError.textContent = 'Password must be at least 6 characters';
    passwordError.classList.remove('hidden');
    return;
  }

  try {
    const response = await fetch('/api/auth/change-password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ newPassword }),
      credentials: 'same-origin'
    });

    if (!response.ok) {
      const data = await response.json();
      passwordError.textContent = data.error || 'Failed to change password';
      passwordError.classList.remove('hidden');
      passwordSuccess.classList.add('hidden');
      return;
    }

    // Show success message in modal and keep the user in the app
    passwordError.classList.add('hidden');
    passwordSuccess.textContent = 'Password changed successfully.';
    passwordSuccess.classList.remove('hidden');
    resetPasswordForm.style.display = 'none';

    // If this was a forced change, allow closing the modal now and
    // automatically close after a short delay so the user continues
    requirePasswordChange = false;
    setTimeout(() => {
      closeResetPasswordModal();
    }, 2000);
  } catch (err) {
    console.error('Change password error:', err);
    passwordError.textContent = 'An error occurred. Please try again.';
    passwordError.classList.remove('hidden');
    passwordSuccess.classList.add('hidden');
  }
});

// (logout-after-reset button removed from UI)

// User Profile / API Token modal functionality
const userProfileBtn = document.getElementById('user-profile-btn');
const userProfileModal = document.getElementById('user-profile-modal');
const closeUserProfileModalBtn = document.getElementById('close-user-profile-modal');
const userProfileForm = document.getElementById('user-profile-form');
const profileEmailInput = document.getElementById('profile-email');
const tokenValiditySelect = document.getElementById('token-validity-select');
const apiTokenStatus = document.getElementById('api-token-status');
const apiTokenLast4 = document.getElementById('api-token-last4');
const apiTokenExpires = document.getElementById('api-token-expires');
const apiTokenDisplaySection = document.getElementById('api-token-display-section');
const apiTokenOnce = document.getElementById('api-token-once');
const generateApiTokenBtn = document.getElementById('generate-api-token-btn');
const extendApiTokenBtn = document.getElementById('extend-api-token-btn');
const revokeApiTokenBtn = document.getElementById('revoke-api-token-btn');
const copyApiTokenBtn = document.getElementById('copy-api-token-btn');
const userProfileError = document.getElementById('user-profile-error');
const userProfileSuccess = document.getElementById('user-profile-success');

function clearProfileMessages() {
  userProfileError.classList.add('hidden');
  userProfileSuccess.classList.add('hidden');
}

function showProfileError(message) {
  userProfileSuccess.classList.add('hidden');
  userProfileError.textContent = message;
  userProfileError.classList.remove('hidden');
}

function showProfileSuccess(message) {
  userProfileError.classList.add('hidden');
  userProfileSuccess.textContent = message;
  userProfileSuccess.classList.remove('hidden');
}

function formatDateTime(value) {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function updateTokenMetadataUI(metadata) {
  if (!metadata || !metadata.hasToken) {
    apiTokenStatus.textContent = 'No active token';
    apiTokenLast4.textContent = '-';
    apiTokenExpires.textContent = '-';
    extendApiTokenBtn.classList.add('hidden');
    revokeApiTokenBtn.classList.add('hidden');
    return;
  }

  apiTokenStatus.textContent = 'Active';
  apiTokenLast4.textContent = metadata.tokenLast4 ? `••••${metadata.tokenLast4}` : '-';
  apiTokenExpires.textContent = formatDateTime(metadata.expiresAt);
  extendApiTokenBtn.classList.remove('hidden');
  revokeApiTokenBtn.classList.remove('hidden');
}

async function loadApiTokenMetadata() {
  const response = await fetch('/api/auth/api-token', { credentials: 'same-origin' });
  if (!response.ok) {
    throw new Error('Failed to load API token metadata');
  }

  const data = await response.json();
  updateTokenMetadataUI(data.apiToken);
}

function hideTokenValueDisplay() {
  apiTokenDisplaySection.classList.add('hidden');
  apiTokenOnce.value = '';
}

async function generateOrRotateToken() {
  clearProfileMessages();
  const validitySeconds = parseInt(tokenValiditySelect.value, 10);

  const response = await fetch('/api/auth/api-token/generate', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    credentials: 'same-origin',
    body: JSON.stringify({ validitySeconds })
  });

  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || 'Failed to generate token');
  }

  apiTokenOnce.value = data.token;
  apiTokenDisplaySection.classList.remove('hidden');
  updateTokenMetadataUI({
    hasToken: true,
    tokenLast4: data.tokenLast4,
    expiresAt: data.expiresAt
  });
  showProfileSuccess(data.warning || 'Token generated. Copy it now; it will not be shown again.');
}

function closeUserProfileModal() {
  userProfileModal.classList.add('hidden');
  clearProfileMessages();
  hideTokenValueDisplay();
}

userProfileBtn.addEventListener('click', async () => {
  userMenu.classList.add('hidden');
  userProfileModal.classList.remove('hidden');
  clearProfileMessages();
  hideTokenValueDisplay();
  profileEmailInput.value = currentUserEmail || '';

  try {
    await loadApiTokenMetadata();
  } catch (err) {
    showProfileError(err.message);
  }
});

closeUserProfileModalBtn.addEventListener('click', closeUserProfileModal);

userProfileModal.addEventListener('click', (e) => {
  if (e.target === userProfileModal) {
    closeUserProfileModal();
  }
});

userProfileForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearProfileMessages();

  try {
    const response = await fetch('/api/auth/profile', {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'same-origin',
      body: JSON.stringify({ email: profileEmailInput.value.trim() })
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'Failed to update profile');
    }

    currentUserEmail = data.user.email || '';
    showProfileSuccess('Email updated successfully.');
  } catch (err) {
    showProfileError(err.message);
  }
});

generateApiTokenBtn.addEventListener('click', async () => {
  try {
    await generateOrRotateToken();
  } catch (err) {
    showProfileError(err.message);
  }
});

extendApiTokenBtn.addEventListener('click', async () => {
  clearProfileMessages();
  const extensionSeconds = parseInt(tokenValiditySelect.value, 10);

  try {
    const response = await fetch('/api/auth/api-token/extend', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'same-origin',
      body: JSON.stringify({ extensionSeconds })
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'Failed to extend token');
    }

    await loadApiTokenMetadata();
    showProfileSuccess('Token expiry updated successfully.');
  } catch (err) {
    showProfileError(err.message);
  }
});

revokeApiTokenBtn.addEventListener('click', async () => {
  clearProfileMessages();

  try {
    const response = await fetch('/api/auth/api-token/revoke', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'same-origin'
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'Failed to revoke token');
    }

    hideTokenValueDisplay();
    await loadApiTokenMetadata();
    showProfileSuccess('API token revoked successfully.');
  } catch (err) {
    showProfileError(err.message);
  }
});

copyApiTokenBtn.addEventListener('click', async () => {
  if (!apiTokenOnce.value) {
    showProfileError('No token available to copy. Generate one first.');
    return;
  }

  try {
    await navigator.clipboard.writeText(apiTokenOnce.value);
    showProfileSuccess('Token copied to clipboard.');
  } catch (err) {
    showProfileError('Failed to copy token to clipboard.');
  }
});

// Load users
async function loadUsers() {
  try {
    const response = await fetch('/api/admin/users', { credentials: 'same-origin' });
    if (!response.ok) throw new Error('Failed to load users');

    const users = await response.json();
    displayUsers(users);
  } catch (err) {
    console.error('Failed to load users:', err);
    showError('Failed to load users: ' + err.message);
    throw err; // Re-throw to stop initialization
  }
}

function displayUsers(users) {
  const tbody = document.getElementById('users-table');
  tbody.innerHTML = '';

  if (users.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="5" class="px-6 py-4 text-center text-gray-500">No users found</td></tr>';
    return;
  }

  users.forEach((user) => {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td class="px-6 py-4">${escapeHtml(user.username)}</td>
      <td class="px-6 py-4">${user.email ? escapeHtml(user.email) : '-'}</td>
      <td class="px-6 py-4">
        <span class="px-2 py-1 rounded text-xs font-semibold bg-blue-100 text-blue-800">
          ${user.role_name || 'No Role'}
        </span>
      </td>
      <td class="px-6 py-4">
        <span class="px-2 py-1 rounded text-xs font-semibold ${
          user.status === 'active'
            ? 'bg-green-100 text-green-800'
            : 'bg-red-100 text-red-800'
        }">
          ${user.status}
        </span>
      </td>
      <td class="px-6 py-4 text-center">
        <button class="edit-btn text-blue-600 hover:text-blue-800 font-semibold text-sm mr-2" data-user-id="${
          user.id
        }">Edit</button>
        <button class="delete-btn text-red-600 hover:text-red-800 font-semibold text-sm" data-user-id="${
          user.id
        }">Delete</button>
      </td>
    `;
    tbody.appendChild(row);
  });

  // Attach edit handlers
  document.querySelectorAll('.edit-btn').forEach((btn) => {
    btn.addEventListener('click', () =>
      editUser(users.find((u) => u.id == btn.dataset.userId))
    );
  });

  // Attach delete handlers
  document.querySelectorAll('.delete-btn').forEach((btn) => {
    btn.addEventListener('click', () => deleteUser(btn.dataset.userId));
  });
}

// User form handling
document.getElementById('user-form').addEventListener('submit', async (e) => {
  e.preventDefault();

  const userId = document.getElementById('user-id').value;
  const username = document.getElementById('username').value;
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;
  const status = document.getElementById('status').value;
  const roleId = document.getElementById('role').value;

  try {
    let response;
    if (userId) {
      // Update user
      const updates = { username, email, status };
      if (roleId) updates.roleId = roleId;

      response = await fetch(`/api/admin/users/${userId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(updates)
      });

      if (password) {
        const pwResponse = await fetch(`/api/admin/users/${userId}/password`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ password })
        });
        if (!pwResponse.ok) throw new Error('Failed to update password');
      }
    } else {
      // Create user
      if (!password) throw new Error('Password required for new users');
      if (!roleId) throw new Error('Role required for new users');

      response = await fetch('/api/admin/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ username, email, password, roleId })
      });
    }

    if (!response.ok) throw new Error('Failed to save user');

    showSuccess(userId ? 'User updated successfully' : 'User created successfully');
    document.getElementById('user-form').reset();
    document.getElementById('user-id').value = '';
    document.getElementById('form-title').textContent = 'Create New User';
    document.getElementById('cancel-edit').classList.add('hidden');
    document.getElementById('password-hint').innerHTML = '(Required for new users)';
    document.getElementById('password').required = true;
    await loadUsers();
  } catch (err) {
    showError(err.message);
  }
});

function editUser(user) {
  currentEditUserId = user.id;
  document.getElementById('user-id').value = user.id;
  document.getElementById('username').value = user.username;
  document.getElementById('email').value = user.email || '';
  document.getElementById('status').value = user.status;
  document.getElementById('role').value = user.role_id || '';
  document.getElementById('password').value = '';
  document.getElementById('form-title').textContent = `Edit User: ${user.username}`;
  document.getElementById('cancel-edit').classList.remove('hidden');
  document.getElementById('password-hint').innerHTML = '(Leave blank to keep current)';
  document.getElementById('password').required = false;

  window.scrollTo({ top: 0, behavior: 'smooth' });
}

document.getElementById('cancel-edit').addEventListener('click', () => {
  document.getElementById('user-form').reset();
  document.getElementById('user-id').value = '';
  document.getElementById('form-title').textContent = 'Create New User';
  document.getElementById('cancel-edit').classList.add('hidden');
  document.getElementById('password-hint').innerHTML = '(Required for new users)';
  document.getElementById('password').required = true;
});

let userToDelete = null;
let roleToDelete = null;

function deleteUser(userId) {
  userToDelete = userId;
  document.getElementById('edit-modal').classList.remove('hidden');
  document.querySelector('#edit-modal h2').textContent = 'Confirm Delete';
  document.querySelector('#edit-modal p').textContent =
    'Are you sure you want to delete this user?';
}

document.getElementById('confirm-delete').addEventListener('click', async () => {
  try {
    let response;
    if (roleToDelete) {
      // Delete role
      response = await fetch(`/api/admin/roles/${roleToDelete}`, {
        method: 'DELETE',
        credentials: 'same-origin'
      });
      if (!response.ok) throw new Error('Failed to delete role');
      showSuccess('Role deleted successfully');
      await loadRolesTab();
      roleToDelete = null;
    } else if (userToDelete) {
      // Delete user
      response = await fetch(`/api/admin/users/${userToDelete}`, {
        method: 'DELETE',
        credentials: 'same-origin'
      });
      if (!response.ok) throw new Error('Failed to delete user');
      showSuccess('User deleted successfully');
      await loadUsers();
      userToDelete = null;
    }

    document.getElementById('edit-modal').classList.add('hidden');
  } catch (err) {
    showError(err.message);
  }
});

document.getElementById('cancel-delete').addEventListener('click', () => {
  document.getElementById('edit-modal').classList.add('hidden');
  userToDelete = null;
  roleToDelete = null;
});

// Load all roles
async function loadRoles() {
  try {
    const response = await fetch('/api/admin/roles', { credentials: 'same-origin' });
    if (!response.ok) throw new Error('Failed to load roles');

    allRoles = await response.json();

    // Populate role dropdown in user form
    const roleSelect = document.getElementById('role');
    roleSelect.innerHTML = '<option value="">Select a role...</option>';

    allRoles.forEach((role) => {
      const option = document.createElement('option');
      option.value = role.id;
      option.textContent = role.name;
      roleSelect.appendChild(option);
    });
  } catch (err) {
    console.error('Failed to load roles:', err);
    showError('Failed to load roles: ' + err.message);
    throw err; // Re-throw to stop initialization
  }
}

// Load roles tab content
async function loadRolesTab() {
  try {
    const response = await fetch('/api/admin/roles', { credentials: 'same-origin' });
    if (!response.ok) throw new Error('Failed to load roles');

    allRoles = await response.json();

    // Also get all permissions for the permission assignment UI
    const permResponse = await fetch('/api/admin/roles/1/permissions', {
      credentials: 'same-origin'
    });
    if (permResponse.ok) {
      allPermissions = [
        { name: 'administration', description: 'Full access to administration and all tools' },
        { name: 'tool_ping', description: 'Access to Ping tool' },
        { name: 'tool_nslookup', description: 'Access to NSLookup tool' },
        { name: 'tool_nslookup_bulk', description: 'Access to NSLookup Bulk tool' },
        { name: 'tool_traceroute', description: 'Access to Traceroute tool' },
        { name: 'tool_mtr', description: 'Access to TCP Traceroute (MTR) tool' },
        { name: 'tool_openssl', description: 'Access to TLS Handshake (OpenSSL) tool' },
        { name: 'tool_curl', description: 'Access to HTTP Timing Stats (Curl) tool' }
      ];
    }

    displayRoles(allRoles);
  } catch (err) {
    showError(err.message);
  }
}

function displayRoles(roles) {
  const tbody = document.getElementById('roles-table');
  tbody.innerHTML = '';

  if (roles.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="3" class="px-6 py-4 text-center text-gray-500">No roles found</td></tr>';
    return;
  }

  roles.forEach((role) => {
    const row = document.createElement('tr');
    const isSystemRole = role.is_system;
    const actionButtons = isSystemRole
      ? `<button class="view-role-btn text-blue-600 hover:text-blue-800 font-semibold text-sm" data-role-id="${role.id}">View Permissions</button>`
      : `<button class="edit-role-btn text-blue-600 hover:text-blue-800 font-semibold text-sm mr-2" data-role-id="${role.id}">Edit</button>
         <button class="view-role-btn text-blue-600 hover:text-blue-800 font-semibold text-sm mr-2" data-role-id="${role.id}">View Permissions</button>
         <button class="delete-role-btn text-red-600 hover:text-red-800 font-semibold text-sm" data-role-id="${role.id}">Delete</button>`;

    row.innerHTML = `
      <td class="px-6 py-4">${escapeHtml(role.name)}${
      isSystemRole ? '<span class="ml-2 text-xs bg-gray-100 px-2 py-1 rounded">System</span>' : ''
    }</td>
      <td class="px-6 py-4">${role.permissionCount || '0'}</td>
      <td class="px-6 py-4 text-center">
        ${actionButtons}
      </td>
    `;
    tbody.appendChild(row);
  });

  // Attach event handlers
  document.querySelectorAll('.edit-role-btn').forEach((btn) => {
    btn.addEventListener('click', () =>
      editRole(allRoles.find((r) => r.id == btn.dataset.roleId))
    );
  });

  document.querySelectorAll('.view-role-btn').forEach((btn) => {
    btn.addEventListener('click', () => loadRolePermissions(btn.dataset.roleId));
  });

  document.querySelectorAll('.delete-role-btn').forEach((btn) => {
    btn.addEventListener('click', () => deleteRoleConfirm(btn.dataset.roleId));
  });
}

// Role form handling
document.getElementById('role-form').addEventListener('submit', async (e) => {
  e.preventDefault();

  const roleId = document.getElementById('role-id').value;
  const name = document.getElementById('role-name').value;
  const description = document.getElementById('role-description').value;

  try {
    let response;
    if (roleId) {
      // Update role
      response = await fetch(`/api/admin/roles/${roleId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ name, description })
      });
    } else {
      // Create role
      response = await fetch('/api/admin/roles', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ name, description })
      });
    }

    if (!response.ok) throw new Error('Failed to save role');

    showSuccess(roleId ? 'Role updated successfully' : 'Role created successfully');
    document.getElementById('role-form').reset();
    document.getElementById('role-id').value = '';
    document.getElementById('role-form-title').textContent = 'Create New Role';
    document.getElementById('role-cancel-edit').classList.add('hidden');
    document.getElementById('role-permissions-container').classList.add('hidden');
    await loadRoles();
    await loadRolesTab();
  } catch (err) {
    showError(err.message);
  }
});

function editRole(role) {
  document.getElementById('role-id').value = role.id;
  document.getElementById('role-name').value = role.name;
  document.getElementById('role-description').value = role.description || '';
  document.getElementById('role-form-title').textContent = `Edit Role: ${role.name}`;
  document.getElementById('role-cancel-edit').classList.remove('hidden');
  document.getElementById('role-permissions-container').classList.add('hidden');

  window.scrollTo({ top: 0, behavior: 'smooth' });
}

document.getElementById('role-cancel-edit').addEventListener('click', () => {
  document.getElementById('role-form').reset();
  document.getElementById('role-id').value = '';
  document.getElementById('role-form-title').textContent = 'Create New Role';
  document.getElementById('role-cancel-edit').classList.add('hidden');
  document.getElementById('role-permissions-container').classList.add('hidden');
});

function deleteRoleConfirm(roleId) {
  const role = allRoles.find((r) => r.id == roleId);
  if (role && role.is_system) {
    showError('Cannot delete system roles');
    return;
  }
  roleToDelete = roleId;
  document.getElementById('edit-modal').classList.remove('hidden');
  document.querySelector('#edit-modal h2').textContent = 'Confirm Delete Role';
  document.querySelector('#edit-modal p').textContent =
    'Are you sure you want to delete this role?';
}

async function loadRolePermissions(roleId) {
  const role = allRoles.find((r) => r.id == roleId);
  if (!role) return;

  try {
    const response = await fetch(`/api/admin/roles/${roleId}/permissions`, {
      credentials: 'same-origin'
    });
    if (!response.ok) throw new Error('Failed to load role permissions');

    const rolePermissions = await response.json();
    const permissionNames = rolePermissions.map((p) => p.name);

    const permList = document.getElementById('role-permissions-list');
    permList.innerHTML = '';

    const allPerms = [
      { name: 'administration', description: 'Full access to administration and all tools' },
      { name: 'tool_ping', description: 'Access to Ping tool' },
      { name: 'tool_nslookup', description: 'Access to NSLookup tool' },
      { name: 'tool_nslookup_bulk', description: 'Access to NSLookup Bulk tool' },
      { name: 'tool_traceroute', description: 'Access to Traceroute tool' },
      { name: 'tool_mtr', description: 'Access to TCP Traceroute (MTR) tool' },
      { name: 'tool_openssl', description: 'Access to TLS Handshake (OpenSSL) tool' },
      { name: 'tool_curl', description: 'Access to HTTP Timing Stats (Curl) tool' }
    ];

    allPerms.forEach((perm) => {
      const hasPermission = permissionNames.includes(perm.name);
      const div = document.createElement('div');
      div.className = 'p-3 border border-gray-200 rounded flex items-start gap-3';
      div.innerHTML = `
        <input
          type="checkbox"
          class="role-permission-checkbox h-4 w-4 text-[#9D003A] rounded mt-1"
          data-role-id="${roleId}"
          data-permission="${perm.name}"
          ${hasPermission ? 'checked' : ''}
          ${role.is_system ? 'disabled' : ''}
        >
        <div>
          <label class="font-semibold text-gray-900 text-sm">${perm.description}</label>
          <p class="text-xs text-gray-500 mt-0.5">${perm.name}</p>
        </div>
      `;
      permList.appendChild(div);
    });

    document.getElementById('selected-role-name').textContent = role.name;
    document.getElementById('role-permissions-container').classList.remove('hidden');

    // Attach permission checkbox handlers
    document.querySelectorAll('.role-permission-checkbox').forEach((checkbox) => {
      checkbox.addEventListener('change', async (e) => {
        const roleId = e.target.dataset.roleId;
        const permission = e.target.dataset.permission;

        try {
          if (e.target.checked) {
            await fetch(`/api/admin/roles/${roleId}/permissions`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              credentials: 'same-origin',
              body: JSON.stringify({ permissionName: permission })
            });
            showSuccess(`Permission granted to role: ${permission}`);
          } else {
            await fetch(`/api/admin/roles/${roleId}/permissions/${permission}`, {
              method: 'DELETE',
              credentials: 'same-origin'
            });
            showSuccess(`Permission revoked from role: ${permission}`);
          }
        } catch (err) {
          showError(err.message);
          e.target.checked = !e.target.checked;
        }
      });
    });
  } catch (err) {
    showError(err.message);
  }
}

// Alert helpers
function showSuccess(message) {
  document.getElementById('success-message').textContent = message;
  document.getElementById('success-alert').classList.remove('hidden');
  setTimeout(() => {
    document.getElementById('success-alert').classList.add('hidden');
  }, 3000);
}

function showError(message) {
  document.getElementById('error-message').textContent = message;
  document.getElementById('error-alert').classList.remove('hidden');
  setTimeout(() => {
    document.getElementById('error-alert').classList.add('hidden');
  }, 5000);
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

