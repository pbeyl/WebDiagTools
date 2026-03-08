const loginForm = document.getElementById('login-form');
const errorAlert = document.getElementById('error-alert');
const errorMessage = document.getElementById('error-message');
const forgotPasswordLink = document.getElementById('forgot-password-link');
const forgotPasswordModal = document.getElementById('forgot-password-modal');
const closeForgotPasswordBtn = document.getElementById('close-forgot-password');
const forgotPasswordForm = document.getElementById('forgot-password-form');
const forgotErrorAlert = document.getElementById('forgot-error-alert');
const forgotErrorMessage = document.getElementById('forgot-error-message');
const forgotSuccessAlert = document.getElementById('forgot-success-alert');

// Login form submission
loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;

  errorAlert.classList.add('hidden');

  try {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ username, password })
    });

    const data = await response.json();

    if (!response.ok) {
      errorMessage.textContent = data.error || 'Login failed';
      errorAlert.classList.remove('hidden');
      return;
    }

    // Redirect to dashboard on successful login
    window.location.href = '/dashboard';
  } catch (err) {
    errorMessage.textContent = 'An error occurred. Please try again.';
    errorAlert.classList.remove('hidden');
    console.error('Login error:', err);
  }
});

// Forgot password modal handling
forgotPasswordLink.addEventListener('click', (e) => {
  e.preventDefault();
  forgotPasswordModal.classList.remove('hidden');
  forgotErrorAlert.classList.add('hidden');
  forgotSuccessAlert.classList.add('hidden');
});

closeForgotPasswordBtn.addEventListener('click', () => {
  forgotPasswordModal.classList.add('hidden');
  forgotPasswordForm.reset();
});

// Forgot password form submission
forgotPasswordForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  const email = document.getElementById('forgot-email').value;
  forgotErrorAlert.classList.add('hidden');
  forgotSuccessAlert.classList.add('hidden');

  try {
    const response = await fetch('/api/auth/forgot-password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ email })
    });

    const data = await response.json();

    if (!response.ok) {
      forgotErrorMessage.textContent = data.error || 'Failed to send reset email';
      forgotErrorAlert.classList.remove('hidden');
      return;
    }

    forgotSuccessAlert.classList.remove('hidden');
    forgotPasswordForm.reset();

    // Auto-close modal after 3 seconds
    setTimeout(() => {
      forgotPasswordModal.classList.add('hidden');
    }, 3000);
  } catch (err) {
    forgotErrorMessage.textContent = 'An error occurred. Please try again.';
    forgotErrorAlert.classList.remove('hidden');
    console.error('Forgot password error:', err);
  }
});

// Close modal when clicking outside
forgotPasswordModal.addEventListener('click', (e) => {
  if (e.target === forgotPasswordModal) {
    forgotPasswordModal.classList.add('hidden');
  }
});

