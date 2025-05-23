// Code generated by mockery. DO NOT EDIT.

package repository

import (
	context "context"

	entity "github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	mock "github.com/stretchr/testify/mock"

	repository "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/repository"
)

// MockUserRepository is an autogenerated mock type for the UserRepository type
type MockUserRepository struct {
	mock.Mock
}

type MockUserRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *MockUserRepository) EXPECT() *MockUserRepository_Expecter {
	return &MockUserRepository_Expecter{mock: &_m.Mock}
}

// Create provides a mock function with given fields: ctx, user
func (_m *MockUserRepository) Create(ctx context.Context, user *entity.User) error {
	ret := _m.Called(ctx, user)

	if len(ret) == 0 {
		panic("no return value specified for Create")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *entity.User) error); ok {
		r0 = rf(ctx, user)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockUserRepository_Create_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Create'
type MockUserRepository_Create_Call struct {
	*mock.Call
}

// Create is a helper method to define mock.On call
//   - ctx context.Context
//   - user *entity.User
func (_e *MockUserRepository_Expecter) Create(ctx interface{}, user interface{}) *MockUserRepository_Create_Call {
	return &MockUserRepository_Create_Call{Call: _e.mock.On("Create", ctx, user)}
}

func (_c *MockUserRepository_Create_Call) Run(run func(ctx context.Context, user *entity.User)) *MockUserRepository_Create_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*entity.User))
	})
	return _c
}

func (_c *MockUserRepository_Create_Call) Return(_a0 error) *MockUserRepository_Create_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockUserRepository_Create_Call) RunAndReturn(run func(context.Context, *entity.User) error) *MockUserRepository_Create_Call {
	_c.Call.Return(run)
	return _c
}

// Delete provides a mock function with given fields: ctx, id
func (_m *MockUserRepository) Delete(ctx context.Context, id entity.ID) error {
	ret := _m.Called(ctx, id)

	if len(ret) == 0 {
		panic("no return value specified for Delete")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, entity.ID) error); ok {
		r0 = rf(ctx, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockUserRepository_Delete_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Delete'
type MockUserRepository_Delete_Call struct {
	*mock.Call
}

// Delete is a helper method to define mock.On call
//   - ctx context.Context
//   - id entity.ID
func (_e *MockUserRepository_Expecter) Delete(ctx interface{}, id interface{}) *MockUserRepository_Delete_Call {
	return &MockUserRepository_Delete_Call{Call: _e.mock.On("Delete", ctx, id)}
}

func (_c *MockUserRepository_Delete_Call) Run(run func(ctx context.Context, id entity.ID)) *MockUserRepository_Delete_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(entity.ID))
	})
	return _c
}

func (_c *MockUserRepository_Delete_Call) Return(_a0 error) *MockUserRepository_Delete_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockUserRepository_Delete_Call) RunAndReturn(run func(context.Context, entity.ID) error) *MockUserRepository_Delete_Call {
	_c.Call.Return(run)
	return _c
}

// EmailExists provides a mock function with given fields: ctx, email
func (_m *MockUserRepository) EmailExists(ctx context.Context, email string) (bool, error) {
	ret := _m.Called(ctx, email)

	if len(ret) == 0 {
		panic("no return value specified for EmailExists")
	}

	var r0 bool
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (bool, error)); ok {
		return rf(ctx, email)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) bool); ok {
		r0 = rf(ctx, email)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, email)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockUserRepository_EmailExists_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'EmailExists'
type MockUserRepository_EmailExists_Call struct {
	*mock.Call
}

// EmailExists is a helper method to define mock.On call
//   - ctx context.Context
//   - email string
func (_e *MockUserRepository_Expecter) EmailExists(ctx interface{}, email interface{}) *MockUserRepository_EmailExists_Call {
	return &MockUserRepository_EmailExists_Call{Call: _e.mock.On("EmailExists", ctx, email)}
}

func (_c *MockUserRepository_EmailExists_Call) Run(run func(ctx context.Context, email string)) *MockUserRepository_EmailExists_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *MockUserRepository_EmailExists_Call) Return(_a0 bool, _a1 error) *MockUserRepository_EmailExists_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockUserRepository_EmailExists_Call) RunAndReturn(run func(context.Context, string) (bool, error)) *MockUserRepository_EmailExists_Call {
	_c.Call.Return(run)
	return _c
}

// ExecuteInTransaction provides a mock function with given fields: ctx, fn
func (_m *MockUserRepository) ExecuteInTransaction(ctx context.Context, fn func(repository.UserRepository) error) error {
	ret := _m.Called(ctx, fn)

	if len(ret) == 0 {
		panic("no return value specified for ExecuteInTransaction")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, func(repository.UserRepository) error) error); ok {
		r0 = rf(ctx, fn)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockUserRepository_ExecuteInTransaction_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ExecuteInTransaction'
type MockUserRepository_ExecuteInTransaction_Call struct {
	*mock.Call
}

// ExecuteInTransaction is a helper method to define mock.On call
//   - ctx context.Context
//   - fn func(repository.UserRepository) error
func (_e *MockUserRepository_Expecter) ExecuteInTransaction(ctx interface{}, fn interface{}) *MockUserRepository_ExecuteInTransaction_Call {
	return &MockUserRepository_ExecuteInTransaction_Call{Call: _e.mock.On("ExecuteInTransaction", ctx, fn)}
}

func (_c *MockUserRepository_ExecuteInTransaction_Call) Run(run func(ctx context.Context, fn func(repository.UserRepository) error)) *MockUserRepository_ExecuteInTransaction_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(func(repository.UserRepository) error))
	})
	return _c
}

func (_c *MockUserRepository_ExecuteInTransaction_Call) Return(_a0 error) *MockUserRepository_ExecuteInTransaction_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockUserRepository_ExecuteInTransaction_Call) RunAndReturn(run func(context.Context, func(repository.UserRepository) error) error) *MockUserRepository_ExecuteInTransaction_Call {
	_c.Call.Return(run)
	return _c
}

// GetByEmail provides a mock function with given fields: ctx, email
func (_m *MockUserRepository) GetByEmail(ctx context.Context, email string) (*entity.User, error) {
	ret := _m.Called(ctx, email)

	if len(ret) == 0 {
		panic("no return value specified for GetByEmail")
	}

	var r0 *entity.User
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (*entity.User, error)); ok {
		return rf(ctx, email)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) *entity.User); ok {
		r0 = rf(ctx, email)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*entity.User)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, email)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockUserRepository_GetByEmail_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetByEmail'
type MockUserRepository_GetByEmail_Call struct {
	*mock.Call
}

// GetByEmail is a helper method to define mock.On call
//   - ctx context.Context
//   - email string
func (_e *MockUserRepository_Expecter) GetByEmail(ctx interface{}, email interface{}) *MockUserRepository_GetByEmail_Call {
	return &MockUserRepository_GetByEmail_Call{Call: _e.mock.On("GetByEmail", ctx, email)}
}

func (_c *MockUserRepository_GetByEmail_Call) Run(run func(ctx context.Context, email string)) *MockUserRepository_GetByEmail_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *MockUserRepository_GetByEmail_Call) Return(_a0 *entity.User, _a1 error) *MockUserRepository_GetByEmail_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockUserRepository_GetByEmail_Call) RunAndReturn(run func(context.Context, string) (*entity.User, error)) *MockUserRepository_GetByEmail_Call {
	_c.Call.Return(run)
	return _c
}

// GetByID provides a mock function with given fields: ctx, id
func (_m *MockUserRepository) GetByID(ctx context.Context, id entity.ID) (*entity.User, error) {
	ret := _m.Called(ctx, id)

	if len(ret) == 0 {
		panic("no return value specified for GetByID")
	}

	var r0 *entity.User
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, entity.ID) (*entity.User, error)); ok {
		return rf(ctx, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, entity.ID) *entity.User); ok {
		r0 = rf(ctx, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*entity.User)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, entity.ID) error); ok {
		r1 = rf(ctx, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockUserRepository_GetByID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetByID'
type MockUserRepository_GetByID_Call struct {
	*mock.Call
}

// GetByID is a helper method to define mock.On call
//   - ctx context.Context
//   - id entity.ID
func (_e *MockUserRepository_Expecter) GetByID(ctx interface{}, id interface{}) *MockUserRepository_GetByID_Call {
	return &MockUserRepository_GetByID_Call{Call: _e.mock.On("GetByID", ctx, id)}
}

func (_c *MockUserRepository_GetByID_Call) Run(run func(ctx context.Context, id entity.ID)) *MockUserRepository_GetByID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(entity.ID))
	})
	return _c
}

func (_c *MockUserRepository_GetByID_Call) Return(_a0 *entity.User, _a1 error) *MockUserRepository_GetByID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockUserRepository_GetByID_Call) RunAndReturn(run func(context.Context, entity.ID) (*entity.User, error)) *MockUserRepository_GetByID_Call {
	_c.Call.Return(run)
	return _c
}

// Update provides a mock function with given fields: ctx, user
func (_m *MockUserRepository) Update(ctx context.Context, user *entity.User) error {
	ret := _m.Called(ctx, user)

	if len(ret) == 0 {
		panic("no return value specified for Update")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *entity.User) error); ok {
		r0 = rf(ctx, user)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockUserRepository_Update_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Update'
type MockUserRepository_Update_Call struct {
	*mock.Call
}

// Update is a helper method to define mock.On call
//   - ctx context.Context
//   - user *entity.User
func (_e *MockUserRepository_Expecter) Update(ctx interface{}, user interface{}) *MockUserRepository_Update_Call {
	return &MockUserRepository_Update_Call{Call: _e.mock.On("Update", ctx, user)}
}

func (_c *MockUserRepository_Update_Call) Run(run func(ctx context.Context, user *entity.User)) *MockUserRepository_Update_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*entity.User))
	})
	return _c
}

func (_c *MockUserRepository_Update_Call) Return(_a0 error) *MockUserRepository_Update_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockUserRepository_Update_Call) RunAndReturn(run func(context.Context, *entity.User) error) *MockUserRepository_Update_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockUserRepository creates a new instance of MockUserRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockUserRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockUserRepository {
	mock := &MockUserRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
