# Go Web Application

A simple web application built with Go, PostgreSQL, and Bootstrap. Features include user authentication, session management, and a dynamic dashboard displaying names from a database.

## Features

- User Authentication (Login/Logout)
- Session Management using Gorilla Sessions
- PostgreSQL Database Integration
- Bootstrap UI
- RESTful API Endpoint
- Secure Password Hashing with bcrypt

## Prerequisites

- Go 1.16 or higher
- PostgreSQL 12 or higher
- `postgres` user with password `postgres` (or update credentials in main.go)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/KBZOZeit3.git
cd KBZOZeit3
```

2. Install dependencies:
```bash
go mod download
```

3. Make sure PostgreSQL is running on localhost:5432

4. Run the application:
```bash
go run main.go
```

The application will automatically:
- Create the database if it doesn't exist
- Create required tables
- Add example data (50 names)

## Usage

1. Access the application at http://localhost:8080
2. Click "Login" to create a new account or log in
3. View the dashboard to see the list of names

## Project Structure

```
.
├── main.go              # Main application file
├── go.mod              # Go module file
├── go.sum              # Go module checksum
└── templates/          # HTML templates
    ├── dashboard.html  # Dashboard template
    ├── home.html      # Home page template
    ├── layout.html    # Base layout template
    └── login.html     # Login form template
```

## API Endpoints

- `GET /api/names` - Returns list of names (requires authentication)

## Security Notes

- Passwords are hashed using bcrypt
- Sessions are managed securely using Gorilla Sessions
- Database credentials should be moved to environment variables in production

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request 