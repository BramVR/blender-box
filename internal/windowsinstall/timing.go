package windowsinstall

import (
	"context"
	"fmt"
	"regexp"
	"sync"
	"time"
)

const maxStepTimings = 32

var stepNamePattern = regexp.MustCompile(`^[a-z][a-z-]{0,63}$`)

// StepTiming is the inclusive wall time one setup worker spent in a named step.
// Steps nest, so a seal includes its PowerShell starts and totals overlap.
type StepTiming struct {
	Step         string `json:"step"`
	Calls        int    `json:"calls"`
	Milliseconds int64  `json:"milliseconds"`
}

type stepTimer struct {
	mu    sync.Mutex
	order []string
	calls map[string]int
	spent map[string]time.Duration
}

type stepTimerKey struct{}

func withStepTimer(ctx context.Context) (context.Context, *stepTimer) {
	timer := &stepTimer{calls: map[string]int{}, spent: map[string]time.Duration{}}
	return context.WithValue(ctx, stepTimerKey{}, timer), timer
}

// timeStep starts timing step when ctx carries a timer; call the result when the step ends.
func timeStep(ctx context.Context, step string) func() {
	timer, _ := ctx.Value(stepTimerKey{}).(*stepTimer)
	if timer == nil {
		return func() {}
	}
	start := time.Now()
	return func() { timer.add(step, time.Since(start)) }
}

// stepTimings reports the timings ctx's timer collected, or nil when ctx carries none.
func stepTimings(ctx context.Context) []StepTiming {
	timer, _ := ctx.Value(stepTimerKey{}).(*stepTimer)
	if timer == nil {
		return nil
	}
	return timer.report()
}

func (t *stepTimer) add(step string, elapsed time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.calls[step] == 0 {
		t.order = append(t.order, step)
	}
	t.calls[step]++
	t.spent[step] += elapsed
}

func (t *stepTimer) report() []StepTiming {
	t.mu.Lock()
	defer t.mu.Unlock()
	steps := make([]StepTiming, 0, len(t.order))
	for _, step := range t.order {
		steps = append(steps, StepTiming{Step: step, Calls: t.calls[step], Milliseconds: t.spent[step].Milliseconds()})
	}
	return steps
}

func validateStepTimings(steps []StepTiming) error {
	if len(steps) > maxStepTimings {
		return fmt.Errorf("excessive step timings")
	}
	seen := map[string]bool{}
	for _, step := range steps {
		if !stepNamePattern.MatchString(step.Step) || seen[step.Step] || step.Calls < 1 || step.Milliseconds < 0 {
			return fmt.Errorf("invalid step timing")
		}
		seen[step.Step] = true
	}
	return nil
}
