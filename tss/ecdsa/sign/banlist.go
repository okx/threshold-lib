package sign

// After the signature verification fails, it is forbidden to continue to sign
// prevent attacks described in CVE-2023-33242 https://www.cve.org/CVERecord?id=CVE-2023-33242
type BanList map[string]struct{}

var BanSignList BanList = make(map[string]struct{})

func (s BanList) Add(id string) {
	s[id] = struct{}{}
}

func (s BanList) Remove(id string) {
	delete(s, id)
}

func (s BanList) Has(id string) bool {
	_, ok := s[id]
	return ok
}

func (s BanList) Clear() {
	s = make(map[string]struct{})
}

func (s BanList) Import(list []string) {
	for _, id := range list {
		s.Add(id)
	}
}

func (s BanList) Export() []string {
	var list []string
	for key := range s {
		list = append(list, key)
	}
	return list
}
