package libgobuster

// Result represents a single gobuster result
/*type Result struct {
	Entity string
	Status int
	Extra  string
	Size   *int64
}*/
type Result struct {
	Entity		string
	Status		int
	Extra		string
	Hash 		string
	Content		string
	Size		*int64
	Category	string
}
// ToString converts the Result to it's textual representation
func (r *Result) ToString(g *Gobuster) (string, error) {
	s, err := g.plugin.ResultToString(g, r)
	if err != nil {
		return "", err
	}
	if s == nil{
		return "", nil
	}
	return *s, nil
}
