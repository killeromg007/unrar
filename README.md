# Anonymous Messaging System

A web application that allows users to send and receive anonymous messages, similar to Tellonym.

## Features

- User registration and authentication
- Send anonymous messages to other users
- View received messages in a clean, modern interface
- Secure password hashing
- Responsive design

## Installation

1. Make sure you have Python 3.8+ installed
2. Install the required packages:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app.py
```

4. Open your browser and navigate to `http://localhost:5000`

## Usage

1. Register for an account
2. Log in with your credentials
3. Send anonymous messages to other users by entering their username
4. View your received messages on your dashboard

## Security Features

- Passwords are securely hashed using Werkzeug's security functions
- Flask-Login handles user sessions securely
- CSRF protection enabled by default
- SQLAlchemy for safe database operations

## Technologies Used

- Flask
- SQLAlchemy
- Flask-Login
- Bootstrap 5
- SQLite
