package kustovalidator

import "errors"

var ErrContractDenied = errors.New("kusto validator contract denied")

func denied() error { return ErrContractDenied }
