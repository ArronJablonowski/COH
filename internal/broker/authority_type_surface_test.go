package broker

import "go/types"

func exposesSecurityType(value types.Type, seen map[types.Type]bool) bool {
	if value == nil || seen[value] {
		return false
	}
	seen[value] = true
	switch typed := value.(type) {
	case *types.Alias:
		if objectFromSensitivePackage(typed.Obj()) {
			return true
		}
		return exposesSecurityType(types.Unalias(typed), seen)
	case *types.Named:
		if objectFromSensitivePackage(typed.Obj()) {
			return true
		}
		for index := range typed.TypeArgs().Len() {
			if exposesSecurityType(typed.TypeArgs().At(index), seen) {
				return true
			}
		}
		for index := range typed.NumMethods() {
			method := typed.Method(index)
			if method.Exported() && (forbiddenCapabilityNames[method.Name()] || exposesSecurityType(method.Type(), seen)) {
				return true
			}
		}
		return exposesSecurityType(typed.Underlying(), seen)
	case *types.Pointer:
		return exposesSecurityType(typed.Elem(), seen)
	case *types.Array:
		return exposesSecurityType(typed.Elem(), seen)
	case *types.Slice:
		return exposesSecurityType(typed.Elem(), seen)
	case *types.Map:
		return exposesSecurityType(typed.Key(), seen) || exposesSecurityType(typed.Elem(), seen)
	case *types.Chan:
		return exposesSecurityType(typed.Elem(), seen)
	case *types.Struct:
		for index := range typed.NumFields() {
			field := typed.Field(index)
			if (field.Exported() || field.Embedded()) &&
				(forbiddenCapabilityNames[field.Name()] || exposesSecurityType(field.Type(), seen)) {
				return true
			}
		}
	case *types.Interface:
		typed.Complete()
		for index := range typed.NumEmbeddeds() {
			if exposesSecurityType(typed.EmbeddedType(index), seen) {
				return true
			}
		}
		for index := range typed.NumMethods() {
			method := typed.Method(index)
			if forbiddenCapabilityNames[method.Name()] || exposesSecurityType(method.Type(), seen) {
				return true
			}
		}
	case *types.Signature:
		if exposesTypeParameters(typed.TypeParams(), seen) ||
			exposesTypeParameters(typed.RecvTypeParams(), seen) ||
			exposesSecurityType(typed.Params(), seen) ||
			exposesSecurityType(typed.Results(), seen) {
			return true
		}
	case *types.Tuple:
		for index := range typed.Len() {
			if exposesSecurityType(typed.At(index).Type(), seen) {
				return true
			}
		}
	case *types.TypeParam:
		return exposesSecurityType(typed.Constraint(), seen)
	case *types.Union:
		for index := range typed.Len() {
			if exposesSecurityType(typed.Term(index).Type(), seen) {
				return true
			}
		}
	}
	return false
}

func exposesTypeParameters(parameters *types.TypeParamList, seen map[types.Type]bool) bool {
	if parameters == nil {
		return false
	}
	for index := range parameters.Len() {
		if exposesSecurityType(parameters.At(index), seen) {
			return true
		}
	}
	return false
}

func objectFromSensitivePackage(object types.Object) bool {
	if object == nil || object.Pkg() == nil {
		return false
	}
	return isSensitiveImport(object.Pkg().Path())
}
