package ui

// RootElement is the root UI element
type RootElement struct {
	*PageHandler
}

// NewRootElement returns a new RootElement
func NewRootElement() *RootElement {
	if currentTheme == nil {
		LightTheme.Apply()
	}

	root := NewPageHandler()

	return &RootElement{
		PageHandler: root,
	}
}
