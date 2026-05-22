// Package runtools is the shared subprocess driver used by every engine
// runner (openvpn, sing-box, future tor). Its job:
//
//   - capture combined stdout+stderr into a ring buffer so we can diagnose
//     failures after the fact without spamming the user with raw logs
//   - watch each line for a success marker (e.g. "Initialization Sequence
//     Completed") and fire OnReady exactly once when seen
//   - tee the raw output to the user's terminal only when Verbose is true
package runtools

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"

	"github.com/KatrielMoses/tun0access/internal/diagnose"
)

// ringMaxBytes caps how much subprocess output we hold for diagnosis. 256 KB
// is plenty for the last few seconds of any VPN client log.
const ringMaxBytes = 256 * 1024

// Options configures a single Run call.
type Options struct {
	// Cmd is the already-configured but not-yet-started command. Its context
	// MUST be the one returned by ReadyContext (or a parent of it) so the
	// deadline cancellation actually terminates the subprocess.
	Cmd *exec.Cmd
	// Verbose controls whether raw subprocess output is also streamed to
	// UserOut. When false, the user only sees our own status messages.
	Verbose bool
	// OnReady is invoked exactly once when a success marker is detected on
	// any output stream. Optional.
	OnReady func()
	// UserOut receives raw lines when Verbose is true. Typically os.Stderr.
	UserOut io.Writer
	// ReadyDeadline, if > 0, kills the subprocess when no success marker has
	// been observed by this duration. Use to bound silent-hang failures.
	ReadyDeadline time.Duration
	// CancelOnDeadline is invoked when ReadyDeadline expires before the
	// success marker fires. The caller's exec.CommandContext context must
	// be wired to a Cancel that this triggers. Optional but strongly
	// recommended when ReadyDeadline is set.
	CancelOnDeadline func()
}

// TimedOut is returned (wrapped) when the subprocess was killed because the
// ReadyDeadline expired. Callers should treat this as "engine started but
// never confirmed connected" rather than a generic error.
var TimedOut = fmt.Errorf("ready deadline exceeded")

// Run starts Cmd, pumps its output, and blocks until it exits. The returned
// string is the captured ring-buffer contents (combined stdout+stderr,
// tail-limited). Callers feed that string to diagnose.Recognise.
func Run(ctx context.Context, opts Options) (string, error) {
	ring := newRingBuffer(ringMaxBytes)

	stdout, err := opts.Cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	stderr, err := opts.Cmd.StderrPipe()
	if err != nil {
		return "", err
	}

	if err := opts.Cmd.Start(); err != nil {
		return "", err
	}

	readyCh := make(chan struct{}, 1)
	var (
		wg        sync.WaitGroup
		readyOnce sync.Once
		fireReady = func() {
			readyOnce.Do(func() {
				if opts.OnReady != nil {
					opts.OnReady()
				}
				select {
				case readyCh <- struct{}{}:
				default:
				}
			})
		}
	)

	// Deadline watchdog: if the success marker doesn't fire in time, cancel
	// the subprocess context so cmd.Wait() returns and we can surface a
	// "engine started but never connected" diagnosis.
	var timedOut bool
	var timedOutMu sync.Mutex
	if opts.ReadyDeadline > 0 && opts.CancelOnDeadline != nil {
		go func() {
			select {
			case <-readyCh:
				// success — let the process keep running
			case <-time.After(opts.ReadyDeadline):
				timedOutMu.Lock()
				timedOut = true
				timedOutMu.Unlock()
				opts.CancelOnDeadline()
			}
		}()
	}

	pump := func(r io.Reader) {
		defer wg.Done()
		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, 0, 64*1024), 1*1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			ring.Write([]byte(line + "\n"))
			if diagnose.IsSuccess(line) {
				fireReady()
			}
			if opts.Verbose && opts.UserOut != nil {
				fmt.Fprintln(opts.UserOut, line)
			}
		}
	}
	wg.Add(2)
	go pump(stdout)
	go pump(stderr)

	waitErr := opts.Cmd.Wait()
	wg.Wait()

	timedOutMu.Lock()
	hit := timedOut
	timedOutMu.Unlock()
	if hit {
		return ring.String(), fmt.Errorf("%w (subprocess killed after timeout)", TimedOut)
	}
	return ring.String(), waitErr
}

// ringBuffer is a simple append-with-truncate buffer. We don't need true
// circular semantics — the captured output is small enough that copying the
// tail on overflow is fine.
type ringBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func newRingBuffer(max int) *ringBuffer {
	return &ringBuffer{max: max}
}

func (r *ringBuffer) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, p...)
	if len(r.buf) > r.max {
		// drop oldest bytes
		extra := len(r.buf) - r.max
		r.buf = r.buf[extra:]
	}
	return len(p), nil
}

func (r *ringBuffer) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return string(r.buf)
}
