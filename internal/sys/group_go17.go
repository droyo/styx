// +build go1.7

package sys

import "os/user"

func groupLookup(gid string) (string, error) {
	g, err := user.LookupGroupId(gid)
	if err != nil {
		return "", err
	}
	return g.Name, nil
}
