document.addEventListener('DOMContentLoaded', function(){
  const form = document.getElementById('loginForm');
  const idInput = document.getElementById('identifier');
  const pwInput = document.getElementById('password');
  const status = document.getElementById('status');
  const toggle = document.getElementById('togglePw');

  toggle.addEventListener('click', () => {
    if (pwInput.type === 'password'){
      pwInput.type = 'text';
      toggle.textContent = 'Hide';
      toggle.setAttribute('aria-label','Hide password');
    } else {
      pwInput.type = 'password';
      toggle.textContent = 'Show';
      toggle.setAttribute('aria-label','Show password');
    }
  });

  function clearErrors(){
    form.querySelectorAll('.error').forEach(e => e.textContent = '');
    status.textContent = '';
  }

  form.addEventListener('submit', function(e){
    e.preventDefault();
    clearErrors();

    const idVal = idInput.value.trim();
    const pwVal = pwInput.value;
    let ok = true;

    if (!idVal){
      idInput.nextElementSibling.textContent = 'Please enter your email or username';
      ok = false;
    }
    if (!pwVal){
      pwInput.parentElement.nextElementSibling.textContent = 'Please enter your password';
      ok = false;
    }
    if (!ok) return;

    status.textContent = 'Signing in…';
    // Simulate async authentication
    setTimeout(() => {
      // demo: accept any password 'password123', otherwise fail
      if (pwVal === 'password123'){
        status.textContent = 'Signed in — redirecting...';
        setTimeout(()=>{
          window.location.href = '#';
        },800);
      } else {
        status.textContent = '';
        pwInput.parentElement.nextElementSibling.textContent = 'Incorrect username or password';
        pwInput.focus();
      }
    }, 900);
  });
});
