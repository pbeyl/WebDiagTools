const resetForm = document.getElementById('reset-form');
const errorAlert = document.getElementById('error-alert');
const errorMessage = document.getElementById('error-message');
const successAlert = document.getElementById('success-alert');
const newPasswordInput = document.getElementById('new-password');
const confirmPasswordInput = document.getElementById('confirm-password');

// Get token from URL
const urlParams = new URLSearchParams(window.location.search);
const resetToken = urlParams.get('token');

if (!resetToken) {
  errorMessage.textContent =
    'Invalid or missing reset token. Please request a new password reset.';
  errorAlert.classList.remove('hidden');
  resetForm.style.display = 'none';
}

// Form submission
resetForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  const newPassword = newPasswordInput.value;
  const confirmPassword = confirmPasswordInput.value;

  errorAlert.classList.add('hidden');
  successAlert.classList.add('hidden');

  // Client-side validation
  if (newPassword !== confirmPassword) {
    errorMessage.textContent = 'Passwords do not match';
    errorAlert.classList.remove('hidden');
    return;
  }

  if (newPassword.length < 8) {
    errorMessage.textContent = 'Password must be at least 8 characters';
    errorAlert.classList.remove('hidden');
    return;
  }

  try {
    const response = await fetch('/api/auth/reset-password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        token: resetToken,
        newPassword
      })
    });

    const data = await response.json();

    if (!response.ok) {
      errorMessage.textContent = data.error || 'Failed to reset password';
      errorAlert.classList.remove('hidden');
      return;
    }

    successAlert.classList.remove('hidden');
    resetForm.style.display = 'none';

    // Redirect to login after 2 seconds
    setTimeout(() => {
      window.location.href = '/';
    }, 2000);
  } catch (err) {
    errorMessage.textContent = 'An error occurred. Please try again.';
    errorAlert.classList.remove('hidden');
    console.error('Reset password error:', err);
  }
});

