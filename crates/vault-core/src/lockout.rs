//! 3-attempts / 24-hour lockout state machine (SPEC.md "Lockout").
//!
//! Pure logic over the header's lockout fields; persistence (header rewrite,
//! registry mirror) is the caller's job.

use crate::VaultError;

pub const MAX_ATTEMPTS: u32 = 3;
pub const LOCKOUT_SECS: u64 = 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LockoutState {
    pub fail_count: u32,
    /// Unix seconds; 0 = not locked.
    pub locked_until: u64,
}

impl LockoutState {
    /// May password entry proceed right now?
    pub fn check(&self, now_unix: u64) -> Result<(), VaultError> {
        if self.locked_until != 0 && now_unix < self.locked_until {
            return Err(VaultError::LockedOut { until_unix: self.locked_until });
        }
        Ok(())
    }

    /// Record a wrong password. Returns the error the caller should surface;
    /// the caller must persist the mutated state before returning it.
    pub fn record_failure(&mut self, now_unix: u64) -> VaultError {
        // A lockout that expired without a successful unlock starts a fresh window.
        if self.locked_until != 0 && now_unix >= self.locked_until {
            self.fail_count = 0;
            self.locked_until = 0;
        }
        self.fail_count += 1;
        if self.fail_count >= MAX_ATTEMPTS {
            self.locked_until = now_unix + LOCKOUT_SECS;
            VaultError::LockedOut { until_unix: self.locked_until }
        } else {
            VaultError::WrongPassword { attempts_left: MAX_ATTEMPTS - self.fail_count }
        }
    }

    /// Successful unlock (password or master key) clears everything.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VaultError;

    #[test]
    fn three_failures_arm_the_lockout() {
        let mut s = LockoutState::default();
        let t = 1_000_000;
        assert!(matches!(s.record_failure(t), VaultError::WrongPassword { attempts_left: 2 }));
        assert!(matches!(s.record_failure(t), VaultError::WrongPassword { attempts_left: 1 }));
        match s.record_failure(t) {
            VaultError::LockedOut { until_unix } => assert_eq!(until_unix, t + LOCKOUT_SECS),
            e => panic!("expected lockout, got {e}"),
        }
        assert!(s.check(t + LOCKOUT_SECS - 1).is_err());
        assert!(s.check(t + LOCKOUT_SECS).is_ok());
    }

    #[test]
    fn clock_rollback_does_not_shorten_the_lockout() {
        let mut s = LockoutState::default();
        let t = 1_800_000_000; // realistic unix time
        for _ in 0..3 {
            s.record_failure(t);
        }
        // attacker sets the clock back a year -> still locked
        assert!(s.check(t - 31_536_000).is_err());
    }

    #[test]
    fn expired_lockout_starts_a_fresh_window() {
        let mut s = LockoutState::default();
        let t = 1_000_000;
        for _ in 0..3 {
            s.record_failure(t);
        }
        let later = t + LOCKOUT_SECS + 5;
        assert!(s.check(later).is_ok());
        assert!(matches!(s.record_failure(later), VaultError::WrongPassword { attempts_left: 2 }));
    }

    #[test]
    fn reset_clears_state() {
        let mut s = LockoutState::default();
        s.record_failure(10);
        s.reset();
        assert_eq!(s, LockoutState::default());
    }
}
