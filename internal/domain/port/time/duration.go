package time

import "time"

// Duration represents a time.Duration with additional functionality
type Duration time.Duration

// Common duration units
const (
	Nanosecond  Duration = Duration(time.Nanosecond)
	Microsecond          = Duration(time.Microsecond)
	Millisecond          = Duration(time.Millisecond)
	Second               = Duration(time.Second)
	Minute               = Duration(time.Minute)
	Hour                 = Duration(time.Hour)
	Day                  = Hour * 24
	Week                 = Day * 7
	Month                = Day * 30
	Year                 = Day * 365
)

// String returns a string representation of the duration
func (d Duration) String() string {
	return time.Duration(d).String()
}

// Std returns the standard library time.Duration
func (d Duration) Std() time.Duration {
	return time.Duration(d)
}
