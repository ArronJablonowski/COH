package kustovalidator

import "errors"

var ErrContractDenied = errors.New("kusto validator contract denied")
var ErrChangedReplay = errors.New("kusto validation idempotency key reused with changed request")

func denied() error { return ErrContractDenied }
