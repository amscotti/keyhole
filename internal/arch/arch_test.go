// Package arch_test locks the keyhole architecture as executable tests so
// `go test` enforces what code review alone cannot:
//
//  1. Single egress: every outbound dial goes through internal/egress. Raw
//     http.Client/http.Transport literals outside egress (and _test.go
//     files) are rejected.
//  2. Request-context discipline: internal/server never mints a background
//     context, and internal/transform does so only in Apply compat shims.
//     (Process roots — cmd shutdown, mcpserver shutdown — own their roots
//     and are out of scope.)
//  3. Layering: the dependency direction is config/egress → fetch/transform
//     → server → cmd, never the reverse.
//
// The golangci depguard/contextcheck rules mirror (1) and (3) for the cases
// they can express; these tests are the backstop that runs with plain `go
// test`, including the config/egress leaf rules that depguard cannot cover
// because tests legitimately wire more (e.g. config tests build an engine).
package arch_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// repoRoot resolves the checkout root from this test file's location
// (internal/arch → two levels up).
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}

// goFiles walks cmd, internal, and e2e collecting .go files. With
// includeTests=false, _test.go files are skipped.
func goFiles(t *testing.T, includeTests bool) []string {
	t.Helper()
	root := repoRoot(t)
	var out []string
	for _, dir := range []string{"cmd", "internal", "e2e"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") {
				return nil
			}
			if !includeTests && strings.HasSuffix(p, "_test.go") {
				return nil
			}
			out = append(out, p)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	return out
}

func parse(t *testing.T, path string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return fset, f
}

// rel shortens an absolute path for failure messages.
func rel(t *testing.T, path string) string {
	t.Helper()
	r, err := filepath.Rel(repoRoot(t), path)
	if err != nil {
		return path
	}
	return r
}

// TestNoRawHTTPConstruction rejects http.Client / http.Transport literals
// outside the egress choke point: a new client built anywhere else bypasses
// the SSRF guard. Test files are excluded (httptest wiring, injected fakes).
// Servers (*http.Server) are inbound listeners, not egress, and are allowed.
func TestNoRawHTTPConstruction(t *testing.T) {
	t.Parallel()
	for _, path := range goFiles(t, false) {
		if strings.Contains(path, string(filepath.Separator)+"egress"+string(filepath.Separator)) {
			continue // the choke point owns all literals
		}
		fset, f := parse(t, path)
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			typ := lit.Type
			if u, ok := typ.(*ast.UnaryExpr); ok && u.Op == token.AND {
				typ = u.X
			}
			sel, ok := typ.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || id.Name != "http" {
				return true
			}
			if sel.Sel.Name == "Client" || sel.Sel.Name == "Transport" {
				t.Errorf("%s:%v: raw http.%s literal — build egress via internal/egress instead",
					rel(t, path), fset.Position(lit.Pos()), sel.Sel.Name)
			}
			return true
		})
	}
}

// backgroundCall reports whether e is context.Background() / context.TODO().
func backgroundCall(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || id.Name != "context" {
		return false
	}
	return sel.Sel.Name == "Background" || sel.Sel.Name == "TODO"
}

// funcBackgrounds returns the names of functions containing a background
// context call, plus whether the file has one outside any function.
func funcBackgrounds(f *ast.File) (inFunc map[string]bool, atTop bool) {
	inFunc = map[string]bool{}
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			if !ok {
				ast.Inspect(decl, func(n ast.Node) bool {
					if e, ok := n.(ast.Expr); ok && backgroundCall(e) {
						atTop = true
						return false
					}
					return true
				})
			}
			continue
		}
		name := fd.Name.Name
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if e, ok := n.(ast.Expr); ok && backgroundCall(e) {
				inFunc[name] = true
				return false
			}
			return true
		})
	}
	return inFunc, atTop
}

// TestRequestContextDiscipline forbids minting background contexts where a
// request context must flow: internal/server never (it always has one), and
// internal/transform only in Apply compat shims (production goes through
// ApplyContext / ApplyDirect).
func TestRequestContextDiscipline(t *testing.T) {
	t.Parallel()
	for _, dir := range []string{"internal/server", "internal/transform"} {
		for _, path := range goFiles(t, false) {
			relPath := filepath.ToSlash(rel(t, path))
			if relPath != dir && !strings.HasPrefix(relPath, dir+"/") {
				continue
			}
			_, f := parse(t, path)
			inFunc, atTop := funcBackgrounds(f)
			if atTop {
				t.Errorf("%s: context.Background() at file scope in request path", relPath)
			}
			for name := range inFunc {
				if strings.HasPrefix(relPath, "internal/server/") {
					t.Errorf("%s: context.Background() in %s — server must propagate the request context", relPath, name)
				} else if name != "Apply" {
					t.Errorf("%s: context.Background() in %s — transforms must take ctx via ApplyContext/ApplyDirect (only Apply shims may)", relPath, name)
				}
			}
		}
	}
}

// layerRule is one directed layering constraint over production files.
type layerRule struct {
	dir  string   // package dir, slash-separated, repo-relative
	deny []string // import paths (prefix when ending in "/") that must not appear
}

// TestPackageLayering locks the dependency direction for production code:
// leaves (config, egress) import nothing internal; fetch/transform never
// import upward; server never imports the entrypoint. Test files are
// excluded — they legitimately wire more (e.g. config tests build an
// engine); depguard covers the test-inclusive subset in lint.
func TestPackageLayering(t *testing.T) {
	t.Parallel()
	rules := []layerRule{
		{dir: "internal/egress", deny: []string{"github.com/amscotti/keyhole/"}},
		{dir: "internal/config", deny: []string{"github.com/amscotti/keyhole/internal/", "github.com/amscotti/keyhole/cmd/"}},
		{dir: "internal/fetch", deny: []string{
			"github.com/amscotti/keyhole/internal/server", "github.com/amscotti/keyhole/internal/transform",
			"github.com/amscotti/keyhole/internal/mcpserver", "github.com/amscotti/keyhole/cmd/",
		}},
		{dir: "internal/transform", deny: []string{
			"github.com/amscotti/keyhole/internal/fetch", "github.com/amscotti/keyhole/internal/server",
			"github.com/amscotti/keyhole/internal/mcpserver", "github.com/amscotti/keyhole/cmd/",
		}},
		{dir: "internal/server", deny: []string{"github.com/amscotti/keyhole/cmd/"}},
		{dir: "internal/mcpserver", deny: []string{"github.com/amscotti/keyhole/cmd/"}},
	}
	files := goFiles(t, false)
	for _, r := range rules {
		for _, path := range files {
			slash := filepath.ToSlash(rel(t, path))
			if slash != r.dir && !strings.HasPrefix(slash, r.dir+"/") {
				continue
			}
			_, f := parse(t, path)
			for _, imp := range f.Imports {
				p := strings.Trim(imp.Path.Value, `"`)
				for _, d := range r.deny {
					bad := p == d || (strings.HasSuffix(d, "/") && strings.HasPrefix(p, d))
					if bad {
						t.Errorf("%s: import %q violates layering (%s must not depend on %s)",
							slash, p, r.dir, d)
					}
				}
			}
		}
	}
}
