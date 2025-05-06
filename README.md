# AuthGuardian

A modern, secure authentication and user management system built with Go, following Domain-Driven Design (DDD) and Hexagonal Architecture principles.

## 🔒 Features

- **Secure Authentication**: JWT-based authentication with refresh tokens
- **User Management**: Registration, login, profile management
- **Email Verification**: Account verification with email confirmation
- **Password Recovery**: Secure password reset functionality
- **Role-based Access Control**: Flexible user permission system
- **Secure by Design**: Following security best practices

## 🏗️ Architecture

This project follows Hexagonal Architecture (Ports & Adapters) to maintain a clean separation of concerns:

```
backend/
├── cmd/               # Application entry points
├── configs/           # Configuration files
├── internal/
│   ├── domain/        # Core business logic and entities
│   ├── port/          # Interfaces (ports)
│   │   ├── input/     # Primary/driving ports
│   │   └── output/    # Secondary/driven ports
│   └── adapter/       # Implementations (adapters)
│       ├── input/     # Primary/driving adapters
│       └── output/    # Secondary/driven adapters
├── migrations/        # Database migration scripts
├── pkg/               # Shared packages
└── test/              # Tests
```

## 🚀 Getting Started

### Prerequisites

- Go 1.18+
- Docker and Docker Compose
- PostgreSQL (or use the provided Docker setup)

### Installation

1. Clone the repository
   ```
   git clone https://github.com/yourusername/auth-guardian.git
   cd auth-guardian
   ```

2. Set up environment variables
   ```
   cp backend/configs/app.env.example backend/configs/app.env
   cp backend/configs/db.env.example backend/configs/db.env
   ```
   
   Edit the config files with your specific settings.

3. Start the application with Docker Compose
   ```
   docker-compose up -d
   ```

4. The API should now be available at `http://localhost:8080/api`

## 🔧 Development

### Running Tests

```
go test ./...
```

### Database Migrations

```
migrate -path migrations -database "postgresql://user:password@localhost:5432/dbname?sslmode=disable" up
```

## 📊 API Endpoints

- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login and get access token
- `POST /api/auth/refresh` - Refresh access token
- `GET /api/users/me` - Get current user profile
- `PUT /api/users/me` - Update user profile

## 🛡️ Security

This project prioritizes security with:

- Password hashing with bcrypt
- JWT with proper expiration
- Refresh token rotation
- CSRF protection
- Rate limiting
- Security headers
- Input validation

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgements

- Go community and all the amazing libraries used in this project 