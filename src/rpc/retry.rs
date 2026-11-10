//! Shared retry policy: how long to keep retrying a failed call, and how
//! long to wait between attempts.
//!
//! The policy lives in [`RpcOptions::retry`](super::RpcOptions::retry), so
//! every backend connected with those options uses it. The backends decide
//! *what* is safe to retry (see [`RpcClient::call_retrying`](super::RpcClient::call_retrying)
//! and the NFS backends); this module only decides *when* and *for how long*.
//!
//! Semantics are close to a "hard" mount with a time limit: a call that fails
//! with a retryable error ([`Error::is_retryable`]) is sent again after an
//! exponentially growing, jittered delay, until it succeeds, fails with a
//! permanent error, or the time budget runs out. In the last case the caller
//! gets [`Error::GaveUp`], which names the operation, how long it tried and
//! the last error.

use std::collections::hash_map::RandomState;
use std::fmt;
use std::hash::{BuildHasher, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

/// Callback invoked on every retry decision; see [`RetryEvent`].
pub type RetryHook = Arc<dyn Fn(&RetryEvent<'_>) + Send + Sync>;

/// How failed calls are retried.
///
/// The defaults give "hard-ish" mount semantics suited to long transfers
/// from a NAS: up to 5 minutes of retries per operation, starting at 0.5 s
/// between attempts and doubling up to 20 s, with jitter.
#[derive(Clone)]
pub struct RetryPolicy {
    /// Total time to keep retrying one operation, measured from its first
    /// failure. The time spent in the attempts themselves counts, so an
    /// operation can take up to `budget` plus one RPC timeout before it gives
    /// up. [`Duration::ZERO`] disables retries: the first error is returned.
    pub budget: Duration,
    /// Delay before the first retry. Each further retry doubles it.
    pub initial_backoff: Duration,
    /// Upper bound on the delay between two attempts.
    pub max_backoff: Duration,
    /// Randomize each delay by +/-20% so many clients do not retry in lockstep.
    pub jitter: bool,
    /// Called on every retry, on recovery and on giving up, for progress
    /// reporting. Runs on the calling thread; keep it short.
    pub on_retry: Option<RetryHook>,
    /// When set and true, retrying stops: a pending backoff wait ends early
    /// (it is checked every 100 ms) and the operation fails with an
    /// `Interrupted` I/O error. For Ctrl-C handling.
    pub cancel: Option<Arc<AtomicBool>>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            budget: Duration::from_secs(300),
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(20),
            jitter: true,
            on_retry: None,
            cancel: None,
        }
    }
}

impl RetryPolicy {
    /// No retries: every error is returned as it happens.
    pub fn none() -> Self {
        Self {
            budget: Duration::ZERO,
            ..Self::default()
        }
    }

    /// Whether retries are enabled at all.
    pub fn enabled(&self) -> bool {
        !self.budget.is_zero()
    }
}

impl fmt::Debug for RetryPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetryPolicy")
            .field("budget", &self.budget)
            .field("initial_backoff", &self.initial_backoff)
            .field("max_backoff", &self.max_backoff)
            .field("jitter", &self.jitter)
            .field("on_retry", &self.on_retry.as_ref().map(|_| "<hook>"))
            .field("cancel", &self.cancel)
            .finish()
    }
}

/// What [`RetryPolicy::on_retry`] is told.
#[derive(Debug)]
pub enum RetryEvent<'a> {
    /// `op` failed with `error`; attempt number `attempt` (2 for the first
    /// retry) follows after `delay`. `elapsed` counts from the first failure.
    Retrying {
        op: &'static str,
        attempt: u32,
        error: &'a Error,
        delay: Duration,
        elapsed: Duration,
        budget: Duration,
    },
    /// `op` succeeded after `attempts` attempts (at least 2).
    Recovered {
        op: &'static str,
        attempts: u32,
        elapsed: Duration,
    },
    /// The budget ran out; `op` fails with [`Error::GaveUp`] wrapping `error`.
    GaveUp {
        op: &'static str,
        attempts: u32,
        error: &'a Error,
        elapsed: Duration,
    },
}

/// Retry state for one operation. Create one per operation, call
/// [`Retrier::backoff`] after each retryable failure and
/// [`Retrier::succeeded`] once it works.
pub struct Retrier<'p> {
    policy: &'p RetryPolicy,
    op: &'static str,
    /// Time of the first failure.
    first_failure: Option<Instant>,
    /// Attempts made so far that failed.
    failures: u32,
    next_delay: Duration,
}

impl<'p> Retrier<'p> {
    pub fn new(policy: &'p RetryPolicy, op: &'static str) -> Self {
        Self {
            policy,
            op,
            first_failure: None,
            failures: 0,
            next_delay: policy.initial_backoff,
        }
    }

    /// Name of the operation being retried.
    pub fn op(&self) -> &'static str {
        self.op
    }

    /// Change the operation name (for example once the request is known).
    pub fn set_op(&mut self, op: &'static str) {
        self.op = op;
    }

    /// Number of failed attempts so far.
    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// The attempt failed with a retryable `error`. Waits for the next
    /// backoff delay and returns `Ok(())` when another attempt should be
    /// made. Returns the error to hand to the caller when retries are
    /// disabled (`error` itself) or the budget is spent ([`Error::GaveUp`]).
    pub fn backoff(&mut self, error: Error) -> Result<()> {
        if !self.policy.enabled() {
            return Err(error);
        }
        let now = Instant::now();
        let first = *self.first_failure.get_or_insert(now);
        self.failures += 1;
        let elapsed = now.duration_since(first);
        let left = self.policy.budget.saturating_sub(elapsed);
        if left.is_zero() {
            self.emit(&RetryEvent::GaveUp {
                op: self.op,
                attempts: self.failures,
                error: &error,
                elapsed,
            });
            return Err(Error::GaveUp {
                op: self.op,
                attempts: self.failures,
                elapsed,
                last: Box::new(error),
            });
        }
        let delay = self.jittered(self.next_delay).min(left);
        self.next_delay = (self.next_delay * 2).min(self.policy.max_backoff);
        self.emit(&RetryEvent::Retrying {
            op: self.op,
            attempt: self.failures + 1,
            error: &error,
            delay,
            elapsed,
            budget: self.policy.budget,
        });
        self.sleep(delay)
    }

    /// Sleep for `d`, waking early (with an `Interrupted` error) when the
    /// policy's cancel flag is set.
    fn sleep(&self, d: Duration) -> Result<()> {
        const SLICE: Duration = Duration::from_millis(100);
        let end = Instant::now() + d;
        loop {
            if self.cancelled() {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    format!("interrupted while retrying {}", self.op),
                )));
            }
            let Some(left) = end.checked_duration_since(Instant::now()) else {
                return Ok(());
            };
            if left.is_zero() {
                return Ok(());
            }
            std::thread::sleep(left.min(SLICE));
        }
    }

    fn cancelled(&self) -> bool {
        self.policy
            .cancel
            .as_ref()
            .is_some_and(|c| c.load(Ordering::SeqCst))
    }

    /// The operation succeeded. Reports recovery when it took retries.
    pub fn succeeded(&self) {
        if let Some(first) = self.first_failure {
            self.emit(&RetryEvent::Recovered {
                op: self.op,
                attempts: self.failures + 1,
                elapsed: first.elapsed(),
            });
        }
    }

    fn emit(&self, ev: &RetryEvent<'_>) {
        if let Some(hook) = &self.policy.on_retry {
            hook(ev);
        }
    }

    fn jittered(&self, d: Duration) -> Duration {
        if !self.policy.jitter || d.is_zero() {
            return d;
        }
        let mut h = RandomState::new().build_hasher();
        h.write_u32(self.failures);
        // 0.8 .. 1.2 in steps of 1/1000.
        let permille = 800 + h.finish() % 401;
        d * permille as u32 / 1000
    }
}

/// Run `attempt` until it succeeds, fails with an error `retry_on` rejects,
/// or `policy`'s budget runs out. `retry_on` sees only errors that are
/// [`Error::is_retryable`].
pub fn run<T>(
    policy: &RetryPolicy,
    op: &'static str,
    retry_on: impl Fn(&Error) -> bool,
    mut attempt: impl FnMut() -> Result<T>,
) -> Result<T> {
    let mut r = Retrier::new(policy, op);
    loop {
        match attempt() {
            Ok(v) => {
                r.succeeded();
                return Ok(v);
            }
            Err(e) if e.is_retryable() && retry_on(&e) => r.backoff(e)?,
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn fast(budget_ms: u64) -> RetryPolicy {
        RetryPolicy {
            budget: Duration::from_millis(budget_ms),
            initial_backoff: Duration::from_millis(5),
            max_backoff: Duration::from_millis(20),
            ..RetryPolicy::default()
        }
    }

    #[test]
    fn cancel_flag_stops_a_long_wait() {
        let flag = Arc::new(AtomicBool::new(false));
        let p = RetryPolicy {
            initial_backoff: Duration::from_secs(30),
            cancel: Some(flag.clone()),
            ..fast(60_000)
        };
        let f = flag.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            f.store(true, Ordering::SeqCst);
        });
        let started = Instant::now();
        let r: Result<()> = run(&p, "READ", |_| true, || Err(Error::Timeout));
        assert!(started.elapsed() < Duration::from_secs(5));
        match r {
            Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::Interrupted),
            other => panic!("expected an interrupt, got {other:?}"),
        }
    }

    #[test]
    fn retries_until_success_and_reports_recovery() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let l = log.clone();
        let mut p = fast(2000);
        p.on_retry = Some(Arc::new(move |e: &RetryEvent<'_>| {
            l.lock().unwrap().push(match e {
                RetryEvent::Retrying { attempt, .. } => format!("retry {attempt}"),
                RetryEvent::Recovered { attempts, .. } => format!("ok {attempts}"),
                RetryEvent::GaveUp { .. } => "gave up".into(),
            })
        }));
        let mut n = 0;
        let v = run(
            &p,
            "TEST",
            |_| true,
            || {
                n += 1;
                if n < 3 { Err(Error::Timeout) } else { Ok(n) }
            },
        )
        .unwrap();
        assert_eq!(v, 3);
        assert_eq!(*log.lock().unwrap(), ["retry 2", "retry 3", "ok 3"]);
    }

    #[test]
    fn permanent_errors_are_not_retried() {
        let mut n = 0;
        let r: Result<()> = run(
            &fast(2000),
            "TEST",
            |_| true,
            || {
                n += 1;
                Err(Error::Nfs(crate::fs::Status::NoEnt))
            },
        );
        assert!(matches!(r, Err(Error::Nfs(crate::fs::Status::NoEnt))));
        assert_eq!(n, 1);
    }

    #[test]
    fn zero_budget_returns_the_first_error() {
        let mut n = 0;
        let r: Result<()> = run(
            &RetryPolicy::none(),
            "TEST",
            |_| true,
            || {
                n += 1;
                Err(Error::Timeout)
            },
        );
        assert!(matches!(r, Err(Error::Timeout)), "{r:?}");
        assert_eq!(n, 1);
    }

    #[test]
    fn exhausted_budget_gives_up_with_context() {
        let started = Instant::now();
        let r: Result<()> = run(&fast(100), "READ", |_| true, || Err(Error::Timeout));
        let e = r.unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(2));
        match &e {
            Error::GaveUp {
                op, attempts, last, ..
            } => {
                assert_eq!(*op, "READ");
                assert!(*attempts >= 2, "{attempts}");
                assert!(matches!(**last, Error::Timeout));
            }
            other => panic!("expected GaveUp, got {other:?}"),
        }
        let msg = e.to_string();
        assert!(msg.contains("gave up") && msg.contains("READ"), "{msg}");
        assert!(!e.is_retryable());
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        let p = RetryPolicy {
            jitter: false,
            ..fast(10_000)
        };
        let mut r = Retrier::new(&p, "T");
        let mut delays = Vec::new();
        for _ in 0..5 {
            delays.push(r.next_delay);
            r.backoff(Error::Timeout).unwrap();
        }
        assert_eq!(
            delays,
            [5, 10, 20, 20, 20].map(Duration::from_millis).to_vec()
        );
    }
}
