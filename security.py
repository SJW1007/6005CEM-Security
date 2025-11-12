import mysql.connector
from datetime import datetime, timedelta
from typing import Optional, Dict, Any


class RateLimiter:
    """Database-backed rate limiter for user actions (e.g., login attempts)."""

    def __init__(
        self,
        connection: mysql.connector.connection.MySQLConnection,
        *,
        window_seconds: int = 15 * 60,
        max_attempts: int = 5,
        lockout_seconds: int = 15 * 60,
        captcha_threshold: int = 3,
        max_backoff_seconds: int = 16,
        max_lock_cycles: int = 2,
        permanent_lock_seconds: Optional[int] = None,
    ) -> None:
        self.connection = connection
        self.window_seconds = window_seconds
        self.max_attempts = max(1, max_attempts)
        self.lockout_seconds = lockout_seconds
        self.captcha_threshold = captcha_threshold
        self.max_backoff_seconds = max_backoff_seconds
        self.max_lock_cycles = max(1, max_lock_cycles)
        self.max_total_attempts = self.max_attempts * self.max_lock_cycles
        self.permanent_lock_seconds = permanent_lock_seconds
        self._ensure_table()

    def _ensure_table(self) -> None:
        cursor = self._get_cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS rate_limit (
                action VARCHAR(64) NOT NULL,
                rate_key VARCHAR(255) NOT NULL,
                window_start DATETIME NOT NULL,
                attempt_count INT NOT NULL DEFAULT 0,
                total_attempts INT NOT NULL DEFAULT 0,
                lock_count INT NOT NULL DEFAULT 0,
                locked_until DATETIME NULL,
                last_failure DATETIME NOT NULL,
                PRIMARY KEY (action, rate_key)
            )
            """
        )
        self.connection.commit()
        # Backwards compatibility for upgrades
        for alter_sql in (
            "ALTER TABLE rate_limit ADD COLUMN total_attempts INT NOT NULL DEFAULT 0",
            "ALTER TABLE rate_limit ADD COLUMN lock_count INT NOT NULL DEFAULT 0",
        ):
            try:
                cursor.execute(alter_sql)
                self.connection.commit()
            except mysql.connector.Error:
                self.connection.rollback()
        cursor.close()

    def _get_cursor(self) -> mysql.connector.cursor.MySQLCursor:
        try:
            # Make sure the connection is still alive
            self.connection.ping(reconnect=True, attempts=1, delay=0)
        except mysql.connector.Error:
            # Attempt a reconnect using the existing connection parameters
            self.connection.reconnect(attempts=3, delay=1)
        return self.connection.cursor()

    @staticmethod
    def _now() -> datetime:
        return datetime.utcnow()

    def check(self, action: str, rate_key: str) -> Dict[str, Any]:
        """Check whether the action is allowed for the given key."""
        cursor = self._get_cursor()
        cursor.execute(
            """
            SELECT window_start,
                   attempt_count,
                   locked_until,
                   lock_count,
                   total_attempts
            FROM rate_limit
            WHERE action=%s AND rate_key=%s
            """,
            (action, rate_key),
        )
        row = cursor.fetchone()
        cursor.close()

        if row is None:
            return {
                "allowed": True,
                "reason": "",
                "wait_seconds": 0,
                "attempt_count": 0,
                "lock_count": 0,
                "total_attempts": 0,
                "attempts_left_before_lock": self.max_attempts,
                "total_attempts_left": self.max_total_attempts,
            }

        window_start, attempt_count, locked_until, lock_count, total_attempts = row
        now = self._now()
        attempts_left_before_lock = max(self.max_attempts - attempt_count, 0)
        total_attempts_left = max(self.max_total_attempts - total_attempts, 0)

        if locked_until and now < locked_until:
            reason = "permanent_lock" if lock_count >= self.max_lock_cycles or total_attempts_left <= 0 else "locked"
            wait_seconds = max(int((locked_until - now).total_seconds()), 1)
            return {
                "allowed": False,
                "reason": reason,
                "wait_seconds": wait_seconds,
                "attempt_count": attempt_count,
                "lock_count": lock_count,
                "total_attempts": total_attempts,
                "attempts_left_before_lock": attempts_left_before_lock,
                "total_attempts_left": total_attempts_left,
            }

        if total_attempts_left <= 0 and lock_count >= self.max_lock_cycles:
            # Safety net for permanent lock if timer expired
            return {
                "allowed": False,
                "reason": "permanent_lock",
                "wait_seconds": 0,
                "attempt_count": attempt_count,
                "lock_count": lock_count,
                "total_attempts": total_attempts,
                "attempts_left_before_lock": 0,
                "total_attempts_left": 0,
            }

        elapsed = (now - window_start).total_seconds()
        if elapsed > self.window_seconds:
            attempt_count = 0
            attempts_left_before_lock = self.max_attempts

        if attempt_count >= self.max_attempts:
            wait_seconds = max(int(self.window_seconds - elapsed), 1)
            return {
                "allowed": False,
                "reason": "rate_limited",
                "wait_seconds": wait_seconds,
                "attempt_count": attempt_count,
                "lock_count": lock_count,
                "total_attempts": total_attempts,
                "attempts_left_before_lock": 0,
                "total_attempts_left": total_attempts_left,
            }

        return {
            "allowed": True,
            "reason": "",
            "wait_seconds": 0,
            "attempt_count": attempt_count,
            "lock_count": lock_count,
            "total_attempts": total_attempts,
            "attempts_left_before_lock": attempts_left_before_lock,
            "total_attempts_left": total_attempts_left,
        }

    def record_failure(self, action: str, rate_key: str) -> Dict[str, Any]:
        """Record a failed attempt for the action/key pair."""
        cursor = self._get_cursor()
        cursor.execute(
            """
            SELECT window_start,
                   attempt_count,
                   locked_until,
                   lock_count,
                   total_attempts
            FROM rate_limit
            WHERE action=%s AND rate_key=%s
            FOR UPDATE
            """,
            (action, rate_key),
        )
        row = cursor.fetchone()
        now = self._now()

        if row is None:
            window_start = now
            attempt_count = 1
            locked_until = None
            lock_count = 0
            total_attempts = 1
        else:
            window_start, attempt_count, locked_until, lock_count, total_attempts = row
            elapsed = (now - window_start).total_seconds()
            if elapsed > self.window_seconds:
                window_start = now
                attempt_count = 1
            else:
                attempt_count += 1
            total_attempts += 1

        locked = False
        lock_reason: Optional[str] = None
        attempts_left_before_lock = max(self.max_attempts - attempt_count, 0)
        total_attempts_left = max(self.max_total_attempts - total_attempts, 0)

        if total_attempts_left <= 0:
            locked = True
            lock_reason = "permanent"
            lock_count += 1
            duration = self.permanent_lock_seconds
            if duration is not None and duration > 0:
                locked_until = now + timedelta(seconds=duration)
            else:
                locked_until = now + timedelta(days=3650)
            attempt_count = self.max_attempts
            attempts_left_before_lock = 0
            total_attempts_left = 0
        elif attempt_count >= self.max_attempts:
            locked = True
            lock_reason = "temporary"
            lock_count += 1
            locked_until = now + timedelta(seconds=self.lockout_seconds)
            attempt_count = self.max_attempts
            attempts_left_before_lock = 0
        else:
            locked_until = None

        if row is None:
            cursor.execute(
                """
                INSERT INTO rate_limit (
                    action,
                    rate_key,
                    window_start,
                    attempt_count,
                    total_attempts,
                    lock_count,
                    locked_until,
                    last_failure
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (action, rate_key, window_start, attempt_count, total_attempts, lock_count, locked_until, now),
            )
        else:
            cursor.execute(
                """
                UPDATE rate_limit
                SET window_start=%s,
                    attempt_count=%s,
                    total_attempts=%s,
                    lock_count=%s,
                    locked_until=%s,
                    last_failure=%s
                WHERE action=%s AND rate_key=%s
                """,
                (window_start, attempt_count, total_attempts, lock_count, locked_until, now, action, rate_key),
            )

        self.connection.commit()
        cursor.close()

        backoff = min(2 ** max(attempt_count - 1, 0), self.max_backoff_seconds)
        if locked:
            backoff = max(backoff, self.max_backoff_seconds)

        result: Dict[str, Any] = {
            "locked": locked,
            "lock_reason": lock_reason,
            "backoff_seconds": backoff,
            "attempt_count": attempt_count,
            "lock_count": lock_count,
            "total_attempts": total_attempts,
            "attempts_left_before_lock": attempts_left_before_lock,
            "total_attempts_left": total_attempts_left,
        }

        if locked:
            if lock_reason == "permanent":
                wait_seconds = 0 if locked_until is None else int(max((locked_until - now).total_seconds(), 0))
            else:
                wait_seconds = self.lockout_seconds
            result["wait_seconds"] = wait_seconds

        return result

    def record_success(self, action: str, rate_key: str) -> None:
        """Reset the failure counter after a successful action."""
        cursor = self._get_cursor()
        cursor.execute(
            "DELETE FROM rate_limit WHERE action=%s AND rate_key=%s",
            (action, rate_key),
        )
        self.connection.commit()
        cursor.close()

    def should_require_captcha(self, action: str, rate_key: str) -> bool:
        """Return True if the user should pass a CAPTCHA before proceeding."""
        if self.captcha_threshold <= 0:
            return False

        cursor = self._get_cursor()
        cursor.execute(
            """
            SELECT window_start, attempt_count, total_attempts
            FROM rate_limit
            WHERE action=%s AND rate_key=%s
            """,
            (action, rate_key),
        )
        row = cursor.fetchone()
        cursor.close()

        if row is None:
            return False

        window_start, attempt_count, total_attempts = row
        attempts = max(attempt_count, total_attempts)
        if attempts < self.captcha_threshold:
            return False

        elapsed = (self._now() - window_start).total_seconds()
        return elapsed <= self.window_seconds

