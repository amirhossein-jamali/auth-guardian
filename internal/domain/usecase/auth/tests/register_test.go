package tests

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	domainErr "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/usecase/auth"

	// Mocks
	mockIdGen "github.com/amirhossein-jamali/auth-guardian/mocks/port/idgenerator"
	mockLogger "github.com/amirhossein-jamali/auth-guardian/mocks/port/logger"
	mockPassword "github.com/amirhossein-jamali/auth-guardian/mocks/port/password"
	mockRepo "github.com/amirhossein-jamali/auth-guardian/mocks/port/repository"
	mockTime "github.com/amirhossein-jamali/auth-guardian/mocks/port/time"
	mockToken "github.com/amirhossein-jamali/auth-guardian/mocks/port/token"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// mockSessionCreator is a mock implementation of the SessionCreator interface
type mockSessionCreator struct {
	mock.Mock
}

func (m *mockSessionCreator) CreateSession(ctx context.Context, userID entity.ID, refreshToken string, userAgent, ip string, expiresAt int64) error {
	args := m.Called(ctx, userID, refreshToken, userAgent, ip, expiresAt)
	return args.Error(0)
}

func TestRegisterUseCase_Execute_Success(t *testing.T) {
	// Arrange - create mocks
	userRepo := mockRepo.NewMockUserRepository(t)
	sessionCreator := new(mockSessionCreator)
	passwordHasher := mockPassword.NewMockPasswordHasher(t)
	tokenService := mockToken.NewMockTokenService(t)
	idGenerator := mockIdGen.NewMockIDGenerator(t)
	timeProvider := mockTime.NewMockTimeProvider(t)
	logger := mockLogger.NewMockLogger(t)

	// Create valid input
	input := auth.RegisterInput{
		Email:     "test@example.com",
		Password:  "Password123!",
		FirstName: "John",
		LastName:  "Doe",
		UserAgent: "Mozilla/5.0",
		IP:        "192.168.1.1",
	}

	// Setup expectations
	currentTime := time.Now()
	userID := "test-user-id"
	hashedPassword := "hashed-password-123"
	accessToken := "access-token-xyz"
	refreshToken := "refresh-token-abc"
	expiresAt := int64(1000)

	// Expected mock calls
	timeProvider.EXPECT().Now().Return(currentTime).Times(2)
	userRepo.EXPECT().EmailExists(mock.Anything, "test@example.com").Return(false, nil)
	passwordHasher.EXPECT().HashPassword("Password123!").Return(hashedPassword, nil)
	idGenerator.EXPECT().GenerateID().Return(userID)
	timeProvider.EXPECT().Now().Return(currentTime)

	// Match the created user
	userRepo.EXPECT().Create(mock.Anything, mock.MatchedBy(func(u *entity.User) bool {
		return u.ID == entity.ID(userID) &&
			u.Email == "test@example.com" &&
			u.FirstName == "John" &&
			u.LastName == "Doe"
	})).Return(nil)

	tokenService.EXPECT().GenerateTokens(userID).Return(accessToken, refreshToken, expiresAt, nil)
	sessionCreator.On("CreateSession", mock.Anything, entity.ID(userID), refreshToken, "Mozilla/5.0", "192.168.1.1", expiresAt).Return(nil)

	// Additional time provider call for final metrics
	timeProvider.EXPECT().Now().Return(currentTime.Add(100 * time.Millisecond))

	// Logger calls
	logger.EXPECT().Info(mock.Anything, mock.Anything).Return()

	// Create use case
	useCase := auth.NewRegisterUseCase(
		userRepo,
		sessionCreator,
		passwordHasher,
		tokenService,
		idGenerator,
		timeProvider,
		logger,
	)

	// Act
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, entity.ID(userID), result.User.ID)
	assert.Equal(t, "test@example.com", result.User.Email)
	assert.Equal(t, "John", result.User.FirstName)
	assert.Equal(t, "Doe", result.User.LastName)
	assert.Equal(t, accessToken, result.AccessToken)
	assert.Equal(t, refreshToken, result.RefreshToken)
	assert.Equal(t, expiresAt, result.ExpiresAt)

	// Verify all expectations were met
	sessionCreator.AssertExpectations(t)
}

func TestRegisterUseCase_Execute_EmailAlreadyExists(t *testing.T) {
	// Arrange - create mocks
	userRepo := mockRepo.NewMockUserRepository(t)
	sessionCreator := new(mockSessionCreator)
	passwordHasher := mockPassword.NewMockPasswordHasher(t)
	tokenService := mockToken.NewMockTokenService(t)
	idGenerator := mockIdGen.NewMockIDGenerator(t)
	timeProvider := mockTime.NewMockTimeProvider(t)
	logger := mockLogger.NewMockLogger(t)

	// Create input with existing email
	input := auth.RegisterInput{
		Email:     "existing@example.com",
		Password:  "Password123!",
		FirstName: "John",
		LastName:  "Doe",
		UserAgent: "Mozilla/5.0",
		IP:        "192.168.1.1",
	}

	// Expected mock calls
	timeProvider.EXPECT().Now().Return(time.Now())
	userRepo.EXPECT().EmailExists(mock.Anything, "existing@example.com").Return(true, nil)

	// Create use case
	useCase := auth.NewRegisterUseCase(
		userRepo,
		sessionCreator,
		passwordHasher,
		tokenService,
		idGenerator,
		timeProvider,
		logger,
	)

	// Act
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, domainErr.ErrEmailAlreadyExists, err)
	assert.Nil(t, result)
}

func TestRegisterUseCase_Execute_InvalidEmail(t *testing.T) {
	// Arrange - create mocks
	userRepo := mockRepo.NewMockUserRepository(t)
	sessionCreator := new(mockSessionCreator)
	passwordHasher := mockPassword.NewMockPasswordHasher(t)
	tokenService := mockToken.NewMockTokenService(t)
	idGenerator := mockIdGen.NewMockIDGenerator(t)
	timeProvider := mockTime.NewMockTimeProvider(t)
	logger := mockLogger.NewMockLogger(t)

	// Create input with invalid email
	input := auth.RegisterInput{
		Email:     "not-an-email",
		Password:  "Password123!",
		FirstName: "John",
		LastName:  "Doe",
		UserAgent: "Mozilla/5.0",
		IP:        "192.168.1.1",
	}

	// Expected mock calls
	timeProvider.EXPECT().Now().Return(time.Now())

	// Create use case
	useCase := auth.NewRegisterUseCase(
		userRepo,
		sessionCreator,
		passwordHasher,
		tokenService,
		idGenerator,
		timeProvider,
		logger,
	)

	// Act
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestRegisterUseCase_Execute_InvalidPassword(t *testing.T) {
	// Arrange - create mocks
	userRepo := mockRepo.NewMockUserRepository(t)
	sessionCreator := new(mockSessionCreator)
	passwordHasher := mockPassword.NewMockPasswordHasher(t)
	tokenService := mockToken.NewMockTokenService(t)
	idGenerator := mockIdGen.NewMockIDGenerator(t)
	timeProvider := mockTime.NewMockTimeProvider(t)
	logger := mockLogger.NewMockLogger(t)

	// Create input with invalid password (too short)
	input := auth.RegisterInput{
		Email:     "test@example.com",
		Password:  "pass",
		FirstName: "John",
		LastName:  "Doe",
		UserAgent: "Mozilla/5.0",
		IP:        "192.168.1.1",
	}

	// Expected mock calls
	timeProvider.EXPECT().Now().Return(time.Now())
	userRepo.EXPECT().EmailExists(mock.Anything, "test@example.com").Return(false, nil)

	// Create use case
	useCase := auth.NewRegisterUseCase(
		userRepo,
		sessionCreator,
		passwordHasher,
		tokenService,
		idGenerator,
		timeProvider,
		logger,
	)

	// Act
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestRegisterUseCase_Execute_UserRepoError(t *testing.T) {
	// Arrange - create mocks
	userRepo := mockRepo.NewMockUserRepository(t)
	sessionCreator := new(mockSessionCreator)
	passwordHasher := mockPassword.NewMockPasswordHasher(t)
	tokenService := mockToken.NewMockTokenService(t)
	idGenerator := mockIdGen.NewMockIDGenerator(t)
	timeProvider := mockTime.NewMockTimeProvider(t)
	logger := mockLogger.NewMockLogger(t)

	// Create valid input
	input := auth.RegisterInput{
		Email:     "test@example.com",
		Password:  "Password123!",
		FirstName: "John",
		LastName:  "Doe",
		UserAgent: "Mozilla/5.0",
		IP:        "192.168.1.1",
	}

	// Setup expectations for repository error
	currentTime := time.Now()
	timeProvider.EXPECT().Now().Return(currentTime)
	userRepo.EXPECT().EmailExists(mock.Anything, "test@example.com").Return(false, errors.New("database error"))
	logger.EXPECT().Error(mock.Anything, mock.Anything).Return()

	// Create use case
	useCase := auth.NewRegisterUseCase(
		userRepo,
		sessionCreator,
		passwordHasher,
		tokenService,
		idGenerator,
		timeProvider,
		logger,
	)

	// Act
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestRegisterUseCase_Execute_CreateSessionError(t *testing.T) {
	// Arrange - create mocks
	userRepo := mockRepo.NewMockUserRepository(t)
	sessionCreator := new(mockSessionCreator)
	passwordHasher := mockPassword.NewMockPasswordHasher(t)
	tokenService := mockToken.NewMockTokenService(t)
	idGenerator := mockIdGen.NewMockIDGenerator(t)
	timeProvider := mockTime.NewMockTimeProvider(t)
	logger := mockLogger.NewMockLogger(t)

	// Create valid input
	input := auth.RegisterInput{
		Email:     "test@example.com",
		Password:  "Password123!",
		FirstName: "John",
		LastName:  "Doe",
		UserAgent: "Mozilla/5.0",
		IP:        "192.168.1.1",
	}

	// Setup expectations
	currentTime := time.Now()
	userID := "test-user-id"
	hashedPassword := "hashed-password-123"
	accessToken := "access-token-xyz"
	refreshToken := "refresh-token-abc"
	expiresAt := int64(1000)

	// Expected mock calls
	timeProvider.EXPECT().Now().Return(currentTime).Times(2)
	userRepo.EXPECT().EmailExists(mock.Anything, "test@example.com").Return(false, nil)
	passwordHasher.EXPECT().HashPassword("Password123!").Return(hashedPassword, nil)
	idGenerator.EXPECT().GenerateID().Return(userID)
	timeProvider.EXPECT().Now().Return(currentTime)

	userRepo.EXPECT().Create(mock.Anything, mock.MatchedBy(func(u *entity.User) bool {
		return u.ID == entity.ID(userID) &&
			u.Email == "test@example.com"
	})).Return(nil)

	tokenService.EXPECT().GenerateTokens(userID).Return(accessToken, refreshToken, expiresAt, nil)

	// Session creator will return an error
	sessionCreator.On("CreateSession", mock.Anything, entity.ID(userID), refreshToken, "Mozilla/5.0", "192.168.1.1", expiresAt).
		Return(errors.New("session creation failed"))

	// Logger should record warning
	logger.EXPECT().Warn(mock.Anything, mock.Anything).Return()

	// Additional time provider call for final metrics
	timeProvider.EXPECT().Now().Return(currentTime.Add(100 * time.Millisecond))

	// Success log should still be recorded even with session error
	logger.EXPECT().Info(mock.Anything, mock.Anything).Return()

	// Create use case
	useCase := auth.NewRegisterUseCase(
		userRepo,
		sessionCreator,
		passwordHasher,
		tokenService,
		idGenerator,
		timeProvider,
		logger,
	)

	// Act - should still succeed despite session error
	result, err := useCase.Execute(context.Background(), input)

	// Assert - operation should succeed despite session creation error
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, entity.ID(userID), result.User.ID)
	assert.Equal(t, accessToken, result.AccessToken)

	// Verify all expectations were met
	sessionCreator.AssertExpectations(t)
}
