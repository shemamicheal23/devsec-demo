# devsec-demo
## Django based class demo about Security essentials required by dev

---

# UAS Authentication Service - Assignment by shema

## Documentation & Design Notes
This service provides a complete User Authentication lifecycle for the `devsec-demo` project.

### Technical Implementation
- **App Name**: `shema`
- **Authentication**: Reuses Django's built-in `auth` framework (`UserCreationForm`, `AuthenticationForm`, `PasswordChangeForm`) to ensure secure defaults and robust password hashing.
- **Access Control**: Protected views across the app use the `@login_required` decorator to prevent unauthorized access to sensitive account information.
- **Security**: 
    - Full CSRF protection on all forms.
    - Input validation handled at form and model boundaries.
    - Secure redirection from protected assets to the login page.
- **Styling**: Implemented with **Bootstrap 5** (via CDN) for a responsive, modern user experience.

### Testing Summary
Core authentication flows are covered by unit tests in `shema/tests.py`, including:
- Successful user registration.
- Login/Logout mechanics.
- Redirection of unauthenticated users from protected pages.

### Setup and Usage
1. **Migrations**: Run `python manage.py migrate` to prepare the database.
2. **Accessing the Service**:
    - Visit `/register/` to create a new account.
    - Visit `/login/` to sign in.
    - Visit `/profile/` to see account details once authenticated.
    - Visit `/password-change/` to update your password.

### AI Disclosure
This implementation was developed with assistance from **Antigravity** (Google DeepMind's AI assistant). The AI assisted in:
- Project structure setup.
- Template generation with Bootstrap 5.
- Writing unit tests for the authentication workflow.
- Documentation and design note drafting.
All security choices and final logic were reviewed and verified by the student.
