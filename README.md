# Vehicle_theft-Complaint_System

A secure, web-based platform for online reporting and management of vehicle theft complaints designed for both citizens and administrators (law enforcement). Built with Python Flask, SQLite, WTForms, Flask-Bcrypt, and Flask-WTF, this project provides a modern, responsive, and role-aware system for streamlined complaint submission, tracking, and resolution.

---

## Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Installation & Setup](#installation--setup)
- [Usage Guide](#usage-guide)
  - [For Users](#for-users)
  - [For Admins](#for-admins)
- [Folder Structure](#folder-structure)
- [Security Considerations](#security-considerations)
- [Customization & Deployment](#customization--deployment)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Features

- **User Features:**
  - Secure user registration and login
  - Vehicle theft complaint submission form with detailed fields
  - User dashboard — view, track, and search complaints with real-time status
  - Complaint details and receipt pages
  - Mobile-responsive interface

- **Admin Features:**
  - Dedicated admin registration and login
  - Admin dashboard with search, filter, and statistics
  - View and update all complaints
  - Detailed complaint management (status change, resolution tracking)
  - User management and bulk actions

- **Security & Reliability:**
  - Passwords hashed with Bcrypt
  - CSRF protection on all forms
  - Parameterized SQL queries to prevent injection
  - Session and role-based access management
  - Audit-friendly complaint status tracking

---

## Tech Stack

| Layer            | Technology/Library           |
|------------------|-----------------------------|
| Backend          | Python 3, Flask              |
| Database         | SQLite                      |
| Forms & Security | WTForms, Flask-WTF, Flask-Bcrypt |
| Frontend Templating | Jinja2, HTML5, CSS3         |
| Styling          | Custom CSS, Font Awesome    |
| Environment Vars | python-dotenv               |

---

## Installation & Setup

### 1. Clone the Repository
  git clone https://github.com/SampathNarne/vehicle_theft_online_complaint_system.git
  cd vehicle-theft-complaint-system

### 2. Create and Activate Virtual Environment

  python -m venv venv

Windows
venv\Scripts\activate

macOS/Linux
source venv/bin/activate


### 3. Install Dependencies

  pip install -r requirements.txt


### 4. Configure Environment Variables

Create a `.env` file in the project root:


  SECRET_KEY=your-very-secure-secret-key
  FLASK_ENV=development
  FLASK_DEBUG=True


Generate a strong secret key using Python:

python -c "import secrets; print(secrets.token_hex(32))"


### 5. Run the Application

  python app.py


Visit [http://localhost:5000](http://localhost:5000) to access the app.

---

## Usage Guide

### For Users

- Register a new account via `/register`
- Log in at `/login`
- Submit a vehicle theft complaint on the dashboard
- Track complaint status and view details

### For Admins

- Register as an admin via `/admin/register`
- Admin login at `/admin/login`
- View and manage all complaints through admin dashboard
- Update complaint statuses and communicate with users

---

## Folder Structure

vehicle-theft-complaint-system/
├── app.py
├── requirements.txt
├── .env.example
├── static/
│ └── styles.css
└── templates/
├── base.html
├── home.html
├── login.html
├── register.html
├── admin_login.html
├── admin_register.html
├── user_dashboard.html
├── admin_dashboard.html
├── submit_complaint.html
├── admin_update_status.html
├── complaint_success.html
└── update_status.html


---

## Security Considerations

- Passwords are stored hashed with Bcrypt—never plaintext
- CSRF protection enabled on all forms with Flask-WTF
- Database queries use parameterized statements to prevent SQL Injection
- Session and role-based access to protect user/admin routes
- Sensitive configuration values stored outside source code as environment variables

---

## Customization & Deployment

- Customize styles in `static/styles.css` and branding in `templates/base.html`
- For production, consider using PostgreSQL or MySQL instead of SQLite
- Use Gunicorn/uWSGI with Nginx or Apache for production deployment
- Enable HTTPS with SSL/TLS certificates
- Dockerize the application for cloud deployment if desired

---

## Troubleshooting

| Issue                                            | Solution                                                      |
|-------------------------------------------------|---------------------------------------------------------------|
| Dependencies not installed                       | Run `pip install -r requirements.txt`                         |
| Secret key missing                               | Ensure `SECRET_KEY` is set in `.env` file                     |
| Database not created                             | Delete existing `.db` file and rerun `python app.py`          |
| Styles not loading                               | Confirm `static/styles.css` exists and is correctly linked    |
| Port in use                                     | Change port in `app.run()` or kill conflicting process        |
| Templates not loading                            | Verify files exist in `templates/` directory                  |

---

## License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).

---

## Contact

For questions, issues, or collaboration, feel free to open an issue or contact the maintainer.

---

*Thank you for choosing Vehicle_theft-Complaint_System!*  
*Developed with ❤️ and Python Flask*  
