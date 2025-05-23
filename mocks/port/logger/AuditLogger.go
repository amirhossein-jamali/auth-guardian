// Code generated by mockery. DO NOT EDIT.

package logger

import (
	context "context"

	mock "github.com/stretchr/testify/mock"
)

// MockAuditLogger is an autogenerated mock type for the AuditLogger type
type MockAuditLogger struct {
	mock.Mock
}

type MockAuditLogger_Expecter struct {
	mock *mock.Mock
}

func (_m *MockAuditLogger) EXPECT() *MockAuditLogger_Expecter {
	return &MockAuditLogger_Expecter{mock: &_m.Mock}
}

// Flush provides a mock function with no fields
func (_m *MockAuditLogger) Flush() error {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Flush")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockAuditLogger_Flush_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Flush'
type MockAuditLogger_Flush_Call struct {
	*mock.Call
}

// Flush is a helper method to define mock.On call
func (_e *MockAuditLogger_Expecter) Flush() *MockAuditLogger_Flush_Call {
	return &MockAuditLogger_Flush_Call{Call: _e.mock.On("Flush")}
}

func (_c *MockAuditLogger_Flush_Call) Run(run func()) *MockAuditLogger_Flush_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockAuditLogger_Flush_Call) Return(_a0 error) *MockAuditLogger_Flush_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockAuditLogger_Flush_Call) RunAndReturn(run func() error) *MockAuditLogger_Flush_Call {
	_c.Call.Return(run)
	return _c
}

// LogSecurityEvent provides a mock function with given fields: ctx, eventType, metadata
func (_m *MockAuditLogger) LogSecurityEvent(ctx context.Context, eventType string, metadata map[string]any) error {
	ret := _m.Called(ctx, eventType, metadata)

	if len(ret) == 0 {
		panic("no return value specified for LogSecurityEvent")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, map[string]any) error); ok {
		r0 = rf(ctx, eventType, metadata)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockAuditLogger_LogSecurityEvent_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'LogSecurityEvent'
type MockAuditLogger_LogSecurityEvent_Call struct {
	*mock.Call
}

// LogSecurityEvent is a helper method to define mock.On call
//   - ctx context.Context
//   - eventType string
//   - metadata map[string]any
func (_e *MockAuditLogger_Expecter) LogSecurityEvent(ctx interface{}, eventType interface{}, metadata interface{}) *MockAuditLogger_LogSecurityEvent_Call {
	return &MockAuditLogger_LogSecurityEvent_Call{Call: _e.mock.On("LogSecurityEvent", ctx, eventType, metadata)}
}

func (_c *MockAuditLogger_LogSecurityEvent_Call) Run(run func(ctx context.Context, eventType string, metadata map[string]any)) *MockAuditLogger_LogSecurityEvent_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(map[string]any))
	})
	return _c
}

func (_c *MockAuditLogger_LogSecurityEvent_Call) Return(_a0 error) *MockAuditLogger_LogSecurityEvent_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockAuditLogger_LogSecurityEvent_Call) RunAndReturn(run func(context.Context, string, map[string]any) error) *MockAuditLogger_LogSecurityEvent_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockAuditLogger creates a new instance of MockAuditLogger. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockAuditLogger(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockAuditLogger {
	mock := &MockAuditLogger{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
