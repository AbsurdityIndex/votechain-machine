package service

import (
	"errors"
	"fmt"
	"net/http"
)

type AppError struct {
	HTTPStatus int
	Code       string
	Message    string
	Retryable  bool
	Cause      error
}

func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

func (e *AppError) Unwrap() error {
	return e.Cause
}

func NewAppError(status int, code, msg string, retryable bool, cause error) *AppError {
	return &AppError{
		HTTPStatus: status,
		Code:       code,
		Message:    msg,
		Retryable:  retryable,
		Cause:      cause,
	}
}

func IsCode(err error, code string) bool {
	var appErr *AppError
	if !errors.As(err, &appErr) {
		return false
	}
	return appErr.Code == code
}

func Internal(msg string, cause error) *AppError {
	return NewAppError(http.StatusInternalServerError, "INTERNAL_ERROR", msg, true, cause)
}
