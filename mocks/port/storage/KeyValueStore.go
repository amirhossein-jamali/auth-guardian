// Code generated by mockery. DO NOT EDIT.

package storage

import (
	context "context"

	mock "github.com/stretchr/testify/mock"

	time "time"
)

// MockKeyValueStore is an autogenerated mock type for the KeyValueStore type
type MockKeyValueStore struct {
	mock.Mock
}

type MockKeyValueStore_Expecter struct {
	mock *mock.Mock
}

func (_m *MockKeyValueStore) EXPECT() *MockKeyValueStore_Expecter {
	return &MockKeyValueStore_Expecter{mock: &_m.Mock}
}

// Delete provides a mock function with given fields: ctx, keys
func (_m *MockKeyValueStore) Delete(ctx context.Context, keys ...string) (int64, error) {
	_va := make([]interface{}, len(keys))
	for _i := range keys {
		_va[_i] = keys[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for Delete")
	}

	var r0 int64
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, ...string) (int64, error)); ok {
		return rf(ctx, keys...)
	}
	if rf, ok := ret.Get(0).(func(context.Context, ...string) int64); ok {
		r0 = rf(ctx, keys...)
	} else {
		r0 = ret.Get(0).(int64)
	}

	if rf, ok := ret.Get(1).(func(context.Context, ...string) error); ok {
		r1 = rf(ctx, keys...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockKeyValueStore_Delete_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Delete'
type MockKeyValueStore_Delete_Call struct {
	*mock.Call
}

// Delete is a helper method to define mock.On call
//   - ctx context.Context
//   - keys ...string
func (_e *MockKeyValueStore_Expecter) Delete(ctx interface{}, keys ...interface{}) *MockKeyValueStore_Delete_Call {
	return &MockKeyValueStore_Delete_Call{Call: _e.mock.On("Delete",
		append([]interface{}{ctx}, keys...)...)}
}

func (_c *MockKeyValueStore_Delete_Call) Run(run func(ctx context.Context, keys ...string)) *MockKeyValueStore_Delete_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]string, len(args)-1)
		for i, a := range args[1:] {
			if a != nil {
				variadicArgs[i] = a.(string)
			}
		}
		run(args[0].(context.Context), variadicArgs...)
	})
	return _c
}

func (_c *MockKeyValueStore_Delete_Call) Return(_a0 int64, _a1 error) *MockKeyValueStore_Delete_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockKeyValueStore_Delete_Call) RunAndReturn(run func(context.Context, ...string) (int64, error)) *MockKeyValueStore_Delete_Call {
	_c.Call.Return(run)
	return _c
}

// Exists provides a mock function with given fields: ctx, keys
func (_m *MockKeyValueStore) Exists(ctx context.Context, keys ...string) (bool, error) {
	_va := make([]interface{}, len(keys))
	for _i := range keys {
		_va[_i] = keys[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for Exists")
	}

	var r0 bool
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, ...string) (bool, error)); ok {
		return rf(ctx, keys...)
	}
	if rf, ok := ret.Get(0).(func(context.Context, ...string) bool); ok {
		r0 = rf(ctx, keys...)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(context.Context, ...string) error); ok {
		r1 = rf(ctx, keys...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockKeyValueStore_Exists_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Exists'
type MockKeyValueStore_Exists_Call struct {
	*mock.Call
}

// Exists is a helper method to define mock.On call
//   - ctx context.Context
//   - keys ...string
func (_e *MockKeyValueStore_Expecter) Exists(ctx interface{}, keys ...interface{}) *MockKeyValueStore_Exists_Call {
	return &MockKeyValueStore_Exists_Call{Call: _e.mock.On("Exists",
		append([]interface{}{ctx}, keys...)...)}
}

func (_c *MockKeyValueStore_Exists_Call) Run(run func(ctx context.Context, keys ...string)) *MockKeyValueStore_Exists_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]string, len(args)-1)
		for i, a := range args[1:] {
			if a != nil {
				variadicArgs[i] = a.(string)
			}
		}
		run(args[0].(context.Context), variadicArgs...)
	})
	return _c
}

func (_c *MockKeyValueStore_Exists_Call) Return(_a0 bool, _a1 error) *MockKeyValueStore_Exists_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockKeyValueStore_Exists_Call) RunAndReturn(run func(context.Context, ...string) (bool, error)) *MockKeyValueStore_Exists_Call {
	_c.Call.Return(run)
	return _c
}

// Get provides a mock function with given fields: ctx, key
func (_m *MockKeyValueStore) Get(ctx context.Context, key string) (string, error) {
	ret := _m.Called(ctx, key)

	if len(ret) == 0 {
		panic("no return value specified for Get")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (string, error)); ok {
		return rf(ctx, key)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) string); ok {
		r0 = rf(ctx, key)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, key)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockKeyValueStore_Get_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Get'
type MockKeyValueStore_Get_Call struct {
	*mock.Call
}

// Get is a helper method to define mock.On call
//   - ctx context.Context
//   - key string
func (_e *MockKeyValueStore_Expecter) Get(ctx interface{}, key interface{}) *MockKeyValueStore_Get_Call {
	return &MockKeyValueStore_Get_Call{Call: _e.mock.On("Get", ctx, key)}
}

func (_c *MockKeyValueStore_Get_Call) Run(run func(ctx context.Context, key string)) *MockKeyValueStore_Get_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *MockKeyValueStore_Get_Call) Return(_a0 string, _a1 error) *MockKeyValueStore_Get_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockKeyValueStore_Get_Call) RunAndReturn(run func(context.Context, string) (string, error)) *MockKeyValueStore_Get_Call {
	_c.Call.Return(run)
	return _c
}

// Set provides a mock function with given fields: ctx, key, value, expiration
func (_m *MockKeyValueStore) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	ret := _m.Called(ctx, key, value, expiration)

	if len(ret) == 0 {
		panic("no return value specified for Set")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, interface{}, time.Duration) error); ok {
		r0 = rf(ctx, key, value, expiration)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockKeyValueStore_Set_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Set'
type MockKeyValueStore_Set_Call struct {
	*mock.Call
}

// Set is a helper method to define mock.On call
//   - ctx context.Context
//   - key string
//   - value interface{}
//   - expiration time.Duration
func (_e *MockKeyValueStore_Expecter) Set(ctx interface{}, key interface{}, value interface{}, expiration interface{}) *MockKeyValueStore_Set_Call {
	return &MockKeyValueStore_Set_Call{Call: _e.mock.On("Set", ctx, key, value, expiration)}
}

func (_c *MockKeyValueStore_Set_Call) Run(run func(ctx context.Context, key string, value interface{}, expiration time.Duration)) *MockKeyValueStore_Set_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(interface{}), args[3].(time.Duration))
	})
	return _c
}

func (_c *MockKeyValueStore_Set_Call) Return(_a0 error) *MockKeyValueStore_Set_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockKeyValueStore_Set_Call) RunAndReturn(run func(context.Context, string, interface{}, time.Duration) error) *MockKeyValueStore_Set_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockKeyValueStore creates a new instance of MockKeyValueStore. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockKeyValueStore(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockKeyValueStore {
	mock := &MockKeyValueStore{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
