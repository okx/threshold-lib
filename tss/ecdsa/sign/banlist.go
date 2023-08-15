package sign

type BanList map[string]struct{}

var EcdsaSignBanList BanList = make(map[string]struct{})

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
	list := []string{}
    for key := range s {
        list = append(list, key)
    }
	return list
}
