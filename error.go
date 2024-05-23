package rumble

import "fmt"

const pkgName = "rumble"

func pkgErr(prefix string, err error) error {
	pkgErr := pkgName
	if prefix != "" {
		pkgErr = fmt.Sprintf("%s: %s", pkgErr, prefix)
	}

	return fmt.Errorf("%s: %v", pkgErr, err)
}
