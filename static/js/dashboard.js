// Authentication and tool-specific code
let requirePasswordChange = false; // set when API tells us force reset is required
let currentUserEmail = '';

document.addEventListener('DOMContentLoaded', async () => {
  // Check authentication and load user info
  await loadUserInfo();

  // Initialize tool UI
  initializeToolUI();
});

async function loadUserInfo() {
  try {
    const response = await fetch('/api/auth/me');
    if (!response.ok) {
      window.location.href = '/';
      return;
    }

    const data = await response.json();
    const username = data.user.username;
    const permissions = data.permissions;
    const forceChange = data.user.forcePasswordChange;
    currentUserEmail = data.user.email || '';

    // Update UI with current user
    document.getElementById('current-user').textContent = username;

    // Show admin link if user has administration permission
    if (permissions.includes('administration')) {
      const desktopAdminLink = document.getElementById('header-admin-link');
      const mobileAdminLink = document.getElementById('admin-link');
      if (desktopAdminLink) desktopAdminLink.classList.remove('hidden');
      if (mobileAdminLink) mobileAdminLink.classList.remove('hidden');
    }

    // Filter tools based on permissions
    filterToolsByPermissions(permissions);

    // record flag so initializeToolUI can handle the forced modal
    if (forceChange) {
      requirePasswordChange = true;
    }
  } catch (err) {
    window.location.href = '/';
  }
}

function filterToolsByPermissions(permissions) {
  const toolSelect = document.getElementById('tool-select');
  const hasAdmin = permissions.includes('administration');

  // Map of permission names to tool values
  const permissionMap = {
    tool_ping: 'ping',
    tool_nslookup: 'nslookup',
    tool_nslookup_bulk: 'nslookup_bulk',
    tool_traceroute: 'traceroute',
    tool_mtr: 'mtr',
    tool_openssl: 'openssl_sconnect',
    tool_curl: 'curl'
  };

  // If not admin, remove tools they don't have access to
  if (!hasAdmin) {
    const allowedTools = permissions
      .filter((p) => p.startsWith('tool_'))
      .map((p) => permissionMap[p]);

    Array.from(toolSelect.options).forEach((option) => {
      if (!allowedTools.includes(option.value)) {
        option.remove();
      }
    });
  }

  // Set to first available option
  if (toolSelect.options.length > 0) {
    toolSelect.value = toolSelect.options[0].value;
  }
}

function initializeToolUI() {
  // Get all elements
  const toolSelect = document.getElementById('tool-select');
  const hostInput = document.getElementById('host-input');
  const runButton = document.getElementById('run-button');
  const copyButton = document.getElementById('copy-button');
  const logoutBtn = document.getElementById('menu-logout');
  const output = document.getElementById('output');

  // Option containers
  const dnsOptions = document.getElementById('dns-options');
  const mtrOptions = document.getElementById('mtr-options');
  const portOption = document.getElementById('port-option');
  const HostContainer = document.getElementById('host-container');
  const bulkHostsContainer = document.getElementById('bulk-hosts-container');
  const pingOptions = document.getElementById('ping-options');

  // Specific inputs
  const dnsServerInput = document.getElementById('dns-server-input');
  const recordTypeSelect = document.getElementById('record-type-select');
  const nslookupDebugCheckbox = document.getElementById('nslookup-debug-checkbox');
  const mtrPortInput = document.getElementById('mtr-port-input');
  const portInput = document.getElementById('port-input');
  const opensslDebugCheckbox = document.getElementById('openssl-debug-checkbox');
  const opensslOption = document.getElementById('openssl-option');
  const bulkHostsInput = document.getElementById('bulk-hosts-input');
  const packetSizeInput = document.getElementById('packet-size-input');
  const dontFragCheckbox = document.getElementById('dont-frag-checkbox');
  const curlOptions = document.getElementById('curl-options');
  const curlHttpsCheckbox = document.getElementById('curl-https-checkbox');

  // Function to update UI based on tool selection
  function updateToolOptions() {
    const selectedTool = toolSelect.value;

    // Hide all optional containers
    dnsOptions.classList.add('hidden');
    mtrOptions.classList.add('hidden');
    portOption.classList.add('hidden');
    opensslOption.classList.add('hidden');
    bulkHostsContainer.classList.add('hidden');
    HostContainer.classList.add('hidden');
    pingOptions.classList.add('hidden');
    curlOptions.classList.add('hidden');

    // Show relevant containers
    if (selectedTool === 'nslookup') {
      HostContainer.classList.remove('hidden');
      dnsOptions.classList.remove('hidden');
    } else if (selectedTool === 'nslookup_bulk') {
      dnsOptions.classList.remove('hidden');
      bulkHostsContainer.classList.remove('hidden');
      HostContainer.classList.add('hidden');
    } else if (selectedTool === 'mtr') {
      HostContainer.classList.remove('hidden');
      mtrOptions.classList.remove('hidden');
    } else if (selectedTool === 'openssl_sconnect') {
      HostContainer.classList.remove('hidden');
      portOption.classList.remove('hidden');
      opensslOption.classList.remove('hidden');
    } else if (selectedTool === 'ping') {
      HostContainer.classList.remove('hidden');
      pingOptions.classList.remove('hidden');
    } else if (selectedTool === 'curl') {
      HostContainer.classList.remove('hidden');
      portOption.classList.remove('hidden');
      curlOptions.classList.remove('hidden');
    } else {
      HostContainer.classList.remove('hidden');
    }
  }

  // Show/hide options on tool change
  toolSelect.addEventListener('change', updateToolOptions);

  // Manually trigger on load to set initial state
  updateToolOptions();

  // User menu toggle
  const userMenuBtn = document.getElementById('user-menu-btn');
  const userMenu = document.getElementById('user-menu');
  userMenuBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    userMenu.classList.toggle('hidden');
  });
  // hide menu when clicking outside
  document.addEventListener('click', (e) => {
    if (!userMenuBtn.contains(e.target) && !userMenu.contains(e.target)) {
      userMenu.classList.add('hidden');
    }
  });

  // logout from menu
  document.getElementById('menu-logout').addEventListener('click', async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
      window.location.href = '/';
    } catch (err) {
      console.error('Logout error:', err);
    }
  });

  // Copy button functionality
  copyButton.addEventListener('click', async () => {
    try {
      const text = output.textContent;
      await navigator.clipboard.writeText(text);

      // Visual feedback
      const originalColor = copyButton.classList.contains('text-white')
        ? 'text-white'
        : 'text-gray-400';
      copyButton.classList.remove(originalColor);
      copyButton.classList.add('text-green-400');
      copyButton.setAttribute('title', 'Copied!');

      // Reset after 2 seconds
      setTimeout(() => {
        copyButton.classList.remove('text-green-400');
        copyButton.classList.add('text-gray-400');
        copyButton.setAttribute('title', 'Copy output to clipboard');
      }, 500);
    } catch (err) {
      console.error('Failed to copy:', err);
      copyButton.classList.add('text-red-400');
      copyButton.setAttribute('title', 'Copy failed');

      setTimeout(() => {
        copyButton.classList.remove('text-red-400');
        copyButton.classList.add('text-gray-400');
        copyButton.setAttribute('title', 'Copy output to clipboard');
      }, 2000);
    }
  });

  // Logout functionality
  logoutBtn.addEventListener('click', async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
      window.location.href = '/';
    } catch (err) {
      console.error('Logout error:', err);
    }
  });

  // Reset Password Modal functionality
  const resetPasswordBtn = document.getElementById('reset-password-btn');
  const resetPasswordModal = document.getElementById('reset-password-modal');
  const cancelResetBtn = document.getElementById('cancel-reset');
  const resetPasswordForm = document.getElementById('reset-password-form');
  const currentPasswordInput = document.getElementById('current-password');
  const newPasswordInput = document.getElementById('new-password');
  const confirmPasswordInput = document.getElementById('confirm-password');
  const passwordError = document.getElementById('password-error');
  const passwordSuccess = document.getElementById('password-success');

  // Open modal
  resetPasswordBtn.addEventListener('click', () => {
    resetPasswordModal.classList.remove('hidden');
    currentPasswordInput.focus();
  });

  // Close modal
  function closeResetPasswordModal() {
    if (requirePasswordChange) {
      // do not allow closing when user is forced to reset
      return;
    }
    resetPasswordModal.classList.add('hidden');
    resetPasswordForm.reset();
    passwordError.classList.add('hidden');
    passwordSuccess.classList.add('hidden');
    resetPasswordForm.style.display = 'block';
    // restore cancel button in case it was hidden for forced resets
    cancelResetBtn.style.display = '';
  }

  cancelResetBtn.addEventListener('click', closeResetPasswordModal);

  // Close modal when clicking outside
  resetPasswordModal.addEventListener('click', (e) => {
    if (e.target === resetPasswordModal) {
      closeResetPasswordModal();
    }
  });

  // if forced password change was flagged during loadUserInfo, lock modal open
  if (requirePasswordChange) {
    resetPasswordModal.classList.remove('hidden');
    cancelResetBtn.style.display = 'none';
  }

  // Handle form submission
  resetPasswordForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const currentPassword = currentPasswordInput.value;
    const newPassword = newPasswordInput.value.trim();
    const confirmPassword = confirmPasswordInput.value.trim();

    if (!currentPassword) {
      passwordError.textContent = 'Current password is required';
      passwordError.classList.remove('hidden');
      return;
    }

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
        body: JSON.stringify({ currentPassword, newPassword })
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
      // success message displayed in `passwordSuccess`; no extra actions element

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
  const apiTokenWarning = document.getElementById('api-token-warning');
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
    const response = await fetch('/api/auth/api-token');
    if (!response.ok) {
      throw new Error('Failed to load API token metadata');
    }

    const data = await response.json();
    updateTokenMetadataUI(data.apiToken);
  }

  function hideTokenValueDisplay() {
    apiTokenDisplaySection.classList.add('hidden');
    apiTokenWarning.classList.add('hidden');
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
      body: JSON.stringify({ validitySeconds })
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'Failed to generate token');
    }

    apiTokenOnce.value = data.token;
    apiTokenDisplaySection.classList.remove('hidden');
    apiTokenWarning.classList.remove('hidden');
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
        }
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

  // Allow pressing Enter in the input field to run the command
  hostInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') e.preventDefault();
  });

  runButton.addEventListener('click', async () => {
    const tool = toolSelect.value;
    const host = hostInput.value;
    const bulkHosts = bulkHostsInput.value;

    // Validate input based on tool type
    if (tool === 'nslookup_bulk') {
      if (!bulkHosts.trim()) {
        output.textContent = 'Error: Please enter one or more hostnames or IP addresses.';
        return;
      }
    } else {
      if (!host) {
        output.textContent = 'Error: Please enter a hostname or IP address.';
        return;
      }
    }

    // Disable button and show loading state
    runButton.disabled = true;
    runButton.textContent = 'Running...';

    if (tool === 'nslookup_bulk') {
      output.textContent = `Running bulk ${tool.replace('_', ' ')}...\n\n`;
    } else {
      output.textContent = `Running ${tool} on ${host}...\n\n`;
    }

    // Collect all optional parameters
    let port = null;
    let protocol = null;
    let debug = false;
    let dnsServer = null;
    let recordType = null;
    let packetSize = null;
    let dontFrag = false;

    if (tool === 'nslookup' || tool === 'nslookup_bulk') {
      dnsServer = dnsServerInput.value;
      debug = nslookupDebugCheckbox.checked;
      recordType = recordTypeSelect.value;
      if (tool === 'nslookup') {
        output.textContent =
          `Running ${tool} on ${host} (type ${recordType})` +
          (dnsServer ? ` using server ${dnsServer}` : '') +
          `...\n\n`;
      } else {
        output.textContent = `Running bulk nslookup (type ${recordType})...\n\n`;
      }
    } else if (tool === 'mtr') {
      port = mtrPortInput.value || '443';
    } else if (tool === 'openssl_sconnect') {
      port = portInput.value || '443';
      debug = opensslDebugCheckbox.checked;
    } else if (tool === 'ping') {
      packetSize = packetSizeInput.value;
      dontFrag = dontFragCheckbox.checked;
    } else if (tool === 'curl') {
      protocol = curlHttpsCheckbox.checked ? 'https' : 'http';
      port = portInput.value;
      const scheme = protocol === 'https' ? 'https://' : 'http://';
      const portSuffix = port ? `:${port}` : '';
      output.textContent = `Running HTTP timing stats on ${scheme}${host}${portSuffix}...\n\n`;
    }

    try {
      const response = await fetch('/api/net-tool', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          tool,
          host: tool === 'nslookup_bulk' ? undefined : host,
          hosts: tool === 'nslookup_bulk' ? bulkHosts : undefined,
          dnsServer: dnsServer || undefined,
          recordType: recordType || undefined,
          packetSize: packetSize || undefined,
          dontFrag: dontFrag || undefined,
          port: port || undefined,
          protocol: protocol || undefined,
          debug
        })
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(errorText || `Server responded with status: ${response.status}`);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        const chunk = decoder.decode(value, { stream: true });
        output.textContent += chunk;
        output.scrollTop = output.scrollHeight;
      }
    } catch (error) {
      console.error('Fetch error:', error);
      output.textContent += `\n--- ERROR ---\n${error.message}`;
    } finally {
      runButton.disabled = false;
      runButton.textContent = 'Run';
    }
  });
}

