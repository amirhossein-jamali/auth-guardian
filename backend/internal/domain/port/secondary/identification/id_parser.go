package identification

import "github.com/amirhossein-jamali/auth-guardian/internal/domain/valueobject"

type IDParser interface {
	ParseID(idStr string) (valueobject.ID, error)
}
