package apply

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

type fakeSystemd struct {
	reloads     int
	restarts    []string
	resetFailed int
	active      bool
	failNext    string // "restart" or "reload"
	isActiveE   error
	nrestarts   int
	flapOnApply bool // Restart bumps NRestarts: simulates crash-looping
	loaded      bool
}

func (f *fakeSystemd) DaemonReload(ctx context.Context) error {
	f.reloads++
	if f.failNext == "reload" {
		f.failNext = ""
		return fmt.Errorf("boom")
	}
	return nil
}
func (f *fakeSystemd) Restart(ctx context.Context, unit string) error {
	f.restarts = append(f.restarts, unit)
	if f.failNext == "restart" {
		f.failNext = ""
		return fmt.Errorf("boom")
	}
	if f.flapOnApply && len(f.restarts) == 1 {
		f.nrestarts++ // crash loop under the new policy
	}
	return nil
}
func (f *fakeSystemd) ResetFailed(ctx context.Context, unit string) error {
	f.resetFailed++
	return nil
}
func (f *fakeSystemd) IsActive(ctx context.Context, unit string) (bool, error) {
	return f.active, f.isActiveE
}
func (f *fakeSystemd) Show(ctx context.Context, unit string, props ...string) (map[string]string, error) {
	m := map[string]string{}
	if f.loaded {
		m["ActiveState"] = "active"
	}
	for _, p := range props {
		if p == "NRestarts" {
			m["NRestarts"] = fmt.Sprint(f.nrestarts)
		}
	}
	return m, nil
}

type memStore struct{ files map[string][]byte }

func (m memStore) Read(u string) ([]byte, error) {
	b, ok := m.files[u]
	if !ok {
		return nil, os.ErrNotExist
	}
	return b, nil
}
func (m memStore) Write(u string, c []byte) error {
	m.files[u] = c
	return nil
}
func (m memStore) Remove(u string) error {
	delete(m.files, u)
	return nil
}

// fakeHealth fails from call failFrom onwards (1-based); 0 means never.
type fakeHealth struct {
	calls    int
	failFrom int
}

func (h *fakeHealth) Run(ctx context.Context, argv []string) error {
	h.calls++
	if h.failFrom > 0 && h.calls >= h.failFrom {
		return fmt.Errorf("dead")
	}
	return nil
}

type fakeGuard struct {
	armed    bool
	disarmed bool
	within   time.Duration
}

func (g *fakeGuard) Arm(ctx context.Context, unit string, within time.Duration) (func(context.Context) error, error) {
	g.armed = true
	g.within = within
	return func(context.Context) error { g.disarmed = true; return nil }, nil
}

func loadedActive() *fakeSystemd { return &fakeSystemd{active: true, loaded: true} }

func TestApplySuccess(t *testing.T) {
	sys := loadedActive()
	store := memStore{files: map[string][]byte{}}
	a := &Applier{Systemd: sys, Store: store, Health: &fakeHealth{}, Settle: time.Millisecond}
	res, err := a.Apply(context.Background(), "demo.service", []byte("[Service]\n"), []string{"true"})
	if err != nil || !res.Applied {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if len(sys.restarts) != 1 {
		t.Errorf("restarts = %v", sys.restarts)
	}
}

func TestApplySuccessArmsAndDisarmsGuard(t *testing.T) {
	sys := loadedActive()
	g := &fakeGuard{}
	a := &Applier{Systemd: sys, Store: memStore{files: map[string][]byte{}}, Guard: g, Settle: time.Millisecond}
	if _, err := a.Apply(context.Background(), "demo.service", []byte("x"), nil); err != nil {
		t.Fatal(err)
	}
	if !g.armed || !g.disarmed {
		t.Errorf("guard armed=%v disarmed=%v, want both true", g.armed, g.disarmed)
	}
}

func TestPreflightHealthFailureAbortsBeforeAnyChange(t *testing.T) {
	sys := loadedActive()
	store := memStore{files: map[string][]byte{}}
	a := &Applier{Systemd: sys, Store: store, Health: &fakeHealth{failFrom: 1}}
	res, err := a.Apply(context.Background(), "demo.service", []byte("new"), []string{"check"})
	if err == nil {
		t.Fatal("expected preflight failure")
	}
	if res.RolledBack {
		t.Error("nothing was changed, so nothing should roll back")
	}
	if len(sys.restarts) != 0 {
		t.Errorf("service must not be restarted: %v", sys.restarts)
	}
	if _, exists := store.files["demo.service"]; exists {
		t.Error("drop-in written despite preflight abort")
	}
}

func TestApplyHealthFailureRollsBack(t *testing.T) {
	sys := loadedActive()
	store := memStore{files: map[string][]byte{}}
	// Preflight (call 1) passes; the post-apply check (call 2) fails.
	a := &Applier{Systemd: sys, Store: store, Health: &fakeHealth{failFrom: 2}, Settle: time.Millisecond}
	res, err := a.Apply(context.Background(), "demo.service", []byte("new"), []string{"check-health"})
	if err == nil || !res.RolledBack {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if _, exists := store.files["demo.service"]; exists {
		t.Error("drop-in left behind after rollback")
	}
	if len(sys.restarts) != 2 {
		t.Errorf("expected restart twice (apply + rollback), got %v", sys.restarts)
	}
	if sys.reloads != 2 {
		t.Errorf("expected daemon-reload twice, got %d", sys.reloads)
	}
	if sys.resetFailed != 1 {
		t.Errorf("expected reset-failed once during rollback, got %d", sys.resetFailed)
	}
}

func TestApplyRestoresPreviousDropin(t *testing.T) {
	sys := loadedActive()
	store := memStore{files: map[string][]byte{"demo.service": []byte("old")}}
	a := &Applier{Systemd: sys, Store: store, Health: &fakeHealth{failFrom: 2}}
	_, err := a.Apply(context.Background(), "demo.service", []byte("new"), []string{"check-health"})
	if err == nil {
		t.Fatal("expected failure")
	}
	if got := string(store.files["demo.service"]); got != "old" {
		t.Errorf("previous drop-in not restored: %q", got)
	}
}

func TestApplyInactiveTriggersRollback(t *testing.T) {
	sys := &fakeSystemd{active: false, loaded: true}
	store := memStore{files: map[string][]byte{}}
	a := &Applier{Systemd: sys, Store: store, Health: &fakeHealth{}}
	res, _ := a.Apply(context.Background(), "demo.service", []byte("new"), nil)
	if !res.RolledBack {
		t.Errorf("inactive unit did not roll back: %+v", res)
	}
}

func TestFlappingServiceRollsBack(t *testing.T) {
	sys := loadedActive()
	sys.flapOnApply = true
	store := memStore{files: map[string][]byte{}}
	a := &Applier{Systemd: sys, Store: store, Settle: time.Millisecond}
	res, err := a.Apply(context.Background(), "demo.service", []byte("new"), nil)
	if err == nil || !res.RolledBack {
		t.Fatalf("flapping service must roll back: res=%+v err=%v", res, err)
	}
	if _, exists := store.files["demo.service"]; exists {
		t.Error("drop-in left behind after flapping rollback")
	}
}

func TestUnitNotLoaded(t *testing.T) {
	sys := &fakeSystemd{active: true, loaded: false}
	a := &Applier{Systemd: sys, Store: memStore{files: map[string][]byte{}}}
	_, err := a.Apply(context.Background(), "ghost.service", []byte("x"), nil)
	if err == nil {
		t.Fatal("expected error for unloaded unit")
	}
}

func TestRollbackRemovesAndRestarts(t *testing.T) {
	sys := loadedActive()
	store := memStore{files: map[string][]byte{"demo.service": []byte("x")}}
	a := &Applier{Systemd: sys, Store: store}
	if err := a.Rollback(context.Background(), "demo.service"); err != nil {
		t.Fatal(err)
	}
	if _, exists := store.files["demo.service"]; exists {
		t.Error("drop-in still present")
	}
	if len(sys.restarts) != 1 {
		t.Errorf("restarts = %v", sys.restarts)
	}
}

func TestFSStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := FSStore{Root: dir}
	if _, err := s.Read("a.service"); !os.IsNotExist(err) {
		t.Fatalf("expected IsNotExist for missing drop-in, got %v", err)
	}
	if err := s.Write("a.service", []byte("data")); err != nil {
		t.Fatal(err)
	}
	b, err := s.Read("a.service")
	if err != nil || string(b) != "data" {
		t.Fatalf("read back %q, %v", b, err)
	}
	if err := s.Remove("a.service"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read("a.service"); !os.IsNotExist(err) {
		t.Fatal("expected drop-in removed")
	}
}
