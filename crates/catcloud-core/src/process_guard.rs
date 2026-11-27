use crate::error::{CatError, CatResult};
use crate::paths::AppPaths;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(target_os = "windows")]
use base64::Engine as _;
#[cfg(target_os = "windows")]
use std::ffi::OsStr;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;
#[cfg(target_os = "windows")]
use std::os::windows::io::AsRawHandle;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

/// Default wait window when launching with `--restarting`, giving the previous
/// primary instance enough time to flush state and release its lock.
pub const RESTART_WAIT_TIMEOUT: Duration = Duration::from_secs(12);

/// Fixed Windows named event exposed exclusively by standard installed instances
/// (including UAC-elevated installed instances using `--data-dir %APPDATA%\CatCloud`)
/// so installers/uninstallers can trigger a deterministic cross-IL graceful shutdown
/// without ever affecting portable deployments or isolated sandboxes.
pub const INSTALLED_GRACEFUL_EXIT_EVENT_NAME: &str = r"Local\CatCloud_GracefulExit_Installed_v1";

/// Request metadata filename written inside `<data_dir>/run/` before signaling a live
/// config hot-reload so the running desktop instance knows `req_id` and `allow_l3_restart`.
pub const CONFIG_RELOAD_REQ_FILE: &str = "config_reload_req.json";

/// Structured acknowledgment filename written atomically inside `<data_dir>/run/` by the
/// running desktop instance after executing a live hot-reload request.
pub const CONFIG_RELOAD_ACK_FILE: &str = "config_reload_ack.json";

static CONFIG_RELOAD_REQ_SEQ: AtomicU64 = AtomicU64::new(1);

/// Cross-process live hot-reload request payload persisted under `<data_dir>/run/config_reload_req.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigReloadRequest {
    pub req_id: String,
    pub allow_l3_restart: bool,
    pub created_at_ms: u64,
}

/// Cross-process live hot-reload acknowledgment persisted under `<data_dir>/run/config_reload_ack.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigReloadAck {
    pub req_id: String,
    pub applied: bool,
    pub rejected: bool,
    pub level: Option<String>,
    pub error: Option<String>,
    pub completed_at_ms: u64,
}

/// Outcome of signaling a running desktop instance for live config hot-reload and waiting for its ack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigReloadWaitOutcome {
    /// No live desktop instance accepted the reload signal (safe to fall back to direct controller).
    NotRunning,
    /// The running desktop instance processed the request and persisted a matching acknowledgment.
    Ack(ConfigReloadAck),
    /// A live instance was signaled, but no matching acknowledgment arrived before timeout
    /// (any lingering on-disk request file carrying `req_id` has been cleaned up).
    TimedOut { req_id: String },
}

/// Format the per-`data_dir` Windows named graceful-exit event name for `instance_hash`.
pub fn graceful_exit_event_name_for_hash(instance_hash: &str) -> String {
    format!(r"Local\CatCloud_GracefulExit_{instance_hash}")
}

/// Format the per-`data_dir` Windows named config hot-reload event name for `instance_hash`.
pub fn config_reload_event_name_for_hash(instance_hash: &str) -> String {
    format!(r"Local\CatCloud_ConfigReload_{instance_hash}")
}

/// Compatibility alias for `JobGuard`.
pub type ProcessGuard = JobGuard;

/// Snapshot of the current process's Windows Job Object limits (always `false` on Unix).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobLimitInfo {
    pub in_job: bool,
    pub kill_on_close: bool,
    pub breakaway_ok: bool,
    pub query_failed: bool,
}

/// Strategy used to spawn a detached/restarted self process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpawnMethod {
    Direct,
    Breakaway,
    WmiEscape,
    UnixDetached,
}

/// Result of launching a detached copy of CatCloud (e.g., self-restart or post-update relaunch).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetachedSpawnResult {
    pub method: SpawnMethod,
    pub pid: Option<u32>,
}

/// Outcome of attempting to acquire the per-`data_dir` single-instance lock.
#[derive(Debug)]
pub enum AcquireOutcome {
    /// Current process owns the primary lock for this `canonical_data_dir`.
    Primary(SingleInstanceGuard),
    /// Another primary instance already owns this `canonical_data_dir` and has been signaled to wake.
    SecondaryWokePrimary,
}

/// Compute the deterministic 8-hex-char instance hash from `canonical_data_dir`,
/// matching `AppPaths::from_data_dir` byte-for-byte.
pub fn compute_instance_hash(data_dir: &Path) -> CatResult<String> {
    std::fs::create_dir_all(data_dir)?;
    Ok(compute_instance_hash_readonly(data_dir))
}

fn compute_instance_hash_readonly(data_dir: &Path) -> String {
    let canonical = crate::paths::normalize_os_path(
        &std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf()),
    );
    let mut hasher = Sha256::new();
    hasher.update(canonical.to_string_lossy().to_lowercase().as_bytes());
    let digest = hex::encode(hasher.finalize());
    digest[..8].to_string()
}

// ============================================================================
// JobGuard: deterministic child process lifecycle & zero-zombie cleanup
// ============================================================================

#[cfg(target_os = "windows")]
struct SendHandle(windows_sys::Win32::Foundation::HANDLE);

// SAFETY: Win32 Job, Mutex, and Event kernel handles are safe to share across threads
// when guarded by synchronization or kernel-atomic Win32 wait/signal APIs.
#[cfg(target_os = "windows")]
unsafe impl Send for SendHandle {}
#[cfg(target_os = "windows")]
unsafe impl Sync for SendHandle {}

/// Manages child processes (such as Mihomo core and temporary probe cores) so that
/// normal exit, crash, or hard termination of the parent guarantees zero orphan children.
pub struct JobGuard {
    #[cfg(target_os = "windows")]
    job_handle: SendHandle,
    #[cfg(unix)]
    managed_pgids: Mutex<Vec<i32>>,
    #[cfg(unix)]
    pid_file: Option<PathBuf>,
}

impl std::fmt::Debug for JobGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(target_os = "windows")]
        {
            f.debug_struct("JobGuard")
                .field("active", &(!self.job_handle.0.is_null()))
                .finish()
        }
        #[cfg(unix)]
        {
            let count = self.managed_pgids.lock().map(|g| g.len()).unwrap_or(0);
            f.debug_struct("JobGuard")
                .field("managed_pgids", &count)
                .field("pid_file", &self.pid_file)
                .finish()
        }
    }
}

impl JobGuard {
    /// Create a new process guard.
    /// - Windows: creates an anonymous Win32 Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
    /// - Unix: tracks child process groups for deterministic `SIGTERM -> SIGKILL` cleanup.
    pub fn new() -> CatResult<Self> {
        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
            use windows_sys::Win32::System::JobObjects::{
                CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
                SetInformationJobObject,
            };

            // SAFETY: Creating an anonymous Job Object with default security attributes.
            let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if handle.is_null() {
                let err = unsafe { GetLastError() };
                return Err(CatError::Process(format!(
                    "CreateJobObjectW failed with Win32 error {err}"
                )));
            }

            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

            // SAFETY: `handle` is valid and `info` matches `JobObjectExtendedLimitInformation`.
            let ok = unsafe {
                SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformation,
                    (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if ok == 0 {
                let err = unsafe { GetLastError() };
                unsafe {
                    let _ = CloseHandle(handle);
                }
                return Err(CatError::Process(format!(
                    "SetInformationJobObject(KILL_ON_JOB_CLOSE) failed with Win32 error {err}"
                )));
            }

            Ok(Self {
                job_handle: SendHandle(handle),
            })
        }

        #[cfg(unix)]
        {
            Ok(Self {
                managed_pgids: Mutex::new(Vec::new()),
                pid_file: None,
            })
        }
    }

    /// Create a `JobGuard` with an optional Unix PID tracking file (used on macOS/Linux to
    /// clean up stale orphan processes on subsequent launch if the parent was SIGKILLed).
    pub fn with_pid_file(pid_file: Option<PathBuf>) -> CatResult<Self> {
        #[cfg(target_os = "windows")]
        {
            let _ = pid_file;
            Self::new()
        }
        #[cfg(unix)]
        {
            if let Some(ref path) = pid_file {
                cleanup_stale_pid_file(path);
            }
            Ok(Self {
                managed_pgids: Mutex::new(Vec::new()),
                pid_file,
            })
        }
    }

    /// Configure a `std::process::Command` before spawning a managed child (such as Mihomo):
    /// - Windows: sets `CREATE_NO_WINDOW` to prevent console flashes.
    /// - Unix: places the child in its own process group (`setpgid(0, 0)`) and on Linux
    ///   registers `PR_SET_PDEATHSIG(SIGKILL)` with parent-PID race detection.
    pub fn configure_std_command(cmd: &mut std::process::Command) {
        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let parent_pid = unsafe { libc::getpid() };
            // SAFETY: Only async-signal-safe syscalls (`setpgid`, `prctl`, `getppid`, `_exit`) are called.
            unsafe {
                cmd.pre_exec(move || {
                    if libc::setpgid(0, 0) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    #[cfg(target_os = "linux")]
                    {
                        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        if libc::getppid() != parent_pid {
                            libc::_exit(1);
                        }
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        let _ = parent_pid;
                    }
                    Ok(())
                });
            }
        }
    }

    /// Configure a `tokio::process::Command` with the same isolation guarantees as
    /// `configure_std_command`.
    pub fn configure_tokio_command(cmd: &mut tokio::process::Command) {
        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        #[cfg(unix)]
        {
            let parent_pid = unsafe { libc::getpid() };
            // SAFETY: Only async-signal-safe syscalls are invoked in `pre_exec`.
            unsafe {
                cmd.pre_exec(move || {
                    if libc::setpgid(0, 0) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    #[cfg(target_os = "linux")]
                    {
                        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        if libc::getppid() != parent_pid {
                            libc::_exit(1);
                        }
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        let _ = parent_pid;
                    }
                    Ok(())
                });
            }
        }
    }

    /// Assign a spawned `std::process::Child` to this guard.
    /// On Windows, if `AssignProcessToJobObject` fails, the child is immediately killed and reaped
    /// so no orphan process can ever escape.
    pub fn assign_child(&self, child: &mut std::process::Child) -> CatResult<()> {
        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
            use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;

            let raw_proc: HANDLE = child.as_raw_handle();
            // SAFETY: Both `job_handle` and `raw_proc` are live kernel handles owned by `self` and `child`.
            let ok = unsafe { AssignProcessToJobObject(self.job_handle.0, raw_proc) };
            if ok == 0 {
                let err = unsafe { GetLastError() };
                let _ = child.kill();
                let _ = child.wait();
                return Err(CatError::Process(format!(
                    "AssignProcessToJobObject failed (win32_err={err}); child terminated to prevent orphan"
                )));
            }
            Ok(())
        }

        #[cfg(unix)]
        {
            let pid = child.id() as i32;
            self.register_unix_pgid(pid);
            Ok(())
        }
    }

    /// Assign a spawned `tokio::process::Child` to this guard.
    /// If assignment fails on Windows, the child is immediately killed to prevent orphans.
    pub fn assign_tokio_child(&self, child: &mut tokio::process::Child) -> CatResult<()> {
        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
            use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;

            let Some(raw) = child.raw_handle() else {
                return Err(CatError::Process(
                    "cannot assign tokio child to JobGuard: child already exited".into(),
                ));
            };
            let raw_proc: HANDLE = raw;
            // SAFETY: `job_handle` and `raw_proc` are live handles while `child` has not exited.
            let ok = unsafe { AssignProcessToJobObject(self.job_handle.0, raw_proc) };
            if ok == 0 {
                let err = unsafe { GetLastError() };
                let _ = child.start_kill();
                return Err(CatError::Process(format!(
                    "AssignProcessToJobObject(tokio) failed (win32_err={err}); child terminated to prevent orphan"
                )));
            }
            Ok(())
        }

        #[cfg(unix)]
        {
            if let Some(pid) = child.id() {
                self.register_unix_pgid(pid as i32);
            }
            Ok(())
        }
    }

    /// Assign an existing process by PID to this guard.
    /// If assignment fails on Windows, attempts to terminate the process immediately.
    pub fn assign_pid(&self, pid: u32) -> CatResult<()> {
        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
            use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
            use windows_sys::Win32::System::Threading::{
                OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE, TerminateProcess,
            };

            // SAFETY: Opening process handle with minimum privileges needed for Job assignment and emergency kill.
            let proc_handle =
                unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid) };
            if proc_handle.is_null() {
                let err = unsafe { GetLastError() };
                return Err(CatError::Process(format!(
                    "OpenProcess(pid={pid}) failed with Win32 error {err}"
                )));
            }

            let ok = unsafe { AssignProcessToJobObject(self.job_handle.0, proc_handle) };
            if ok == 0 {
                let err = unsafe { GetLastError() };
                unsafe {
                    let _ = TerminateProcess(proc_handle, 1);
                    let _ = CloseHandle(proc_handle);
                }
                return Err(CatError::Process(format!(
                    "AssignProcessToJobObject(pid={pid}) failed (win32_err={err}); process terminated"
                )));
            }

            unsafe {
                let _ = CloseHandle(proc_handle);
            }
            Ok(())
        }

        #[cfg(unix)]
        {
            self.register_unix_pgid(pid as i32);
            Ok(())
        }
    }

    /// Unregister an exited child PID/PGID from tracking (no-op on Windows, where the Win32
    /// Job Object automatically tracks process lifetimes).
    pub fn unregister_pid(&self, pid: u32) {
        #[cfg(target_os = "windows")]
        {
            let _ = pid;
        }
        #[cfg(unix)]
        {
            let pgid = pid as i32;
            if pgid <= 0 {
                return;
            }
            if let Ok(mut guard) = self.managed_pgids.lock() {
                guard.retain(|&existing| existing != pgid && is_unix_pgid_alive(existing));
            }
            self.sync_unix_pid_file();
        }
    }

    /// Explicitly terminate all processes currently managed by this guard.
    pub fn terminate_all(&self) -> CatResult<()> {
        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::Foundation::GetLastError;
            use windows_sys::Win32::System::JobObjects::TerminateJobObject;

            if self.job_handle.0.is_null() {
                return Ok(());
            }
            // SAFETY: Valid Job handle owned by `self`.
            let ok = unsafe { TerminateJobObject(self.job_handle.0, 1) };
            if ok == 0 {
                let err = unsafe { GetLastError() };
                return Err(CatError::Process(format!(
                    "TerminateJobObject failed with Win32 error {err}"
                )));
            }
            Ok(())
        }

        #[cfg(unix)]
        {
            let pgids: Vec<i32> = {
                let mut guard = self.managed_pgids.lock().unwrap_or_else(|e| e.into_inner());
                let raw = std::mem::take(&mut *guard);
                raw.into_iter()
                    .filter(|&pgid| is_unix_pgid_alive(pgid))
                    .collect()
            };
            for &pgid in &pgids {
                if pgid > 0 {
                    // SAFETY: Sending SIGTERM to child process group created via `setpgid(0, 0)`.
                    unsafe {
                        let _ = libc::kill(-pgid, libc::SIGTERM);
                    }
                }
            }
            if !pgids.is_empty() {
                std::thread::sleep(Duration::from_millis(120));
                for &pgid in &pgids {
                    if pgid > 0 && is_unix_pgid_alive(pgid) {
                        // SAFETY: Escalating to SIGKILL for any lingering processes in the group.
                        unsafe {
                            let _ = libc::kill(-pgid, libc::SIGKILL);
                        }
                    }
                }
            }
            self.sync_unix_pid_file();
            Ok(())
        }
    }

    #[cfg(unix)]
    fn register_unix_pgid(&self, pgid: i32) {
        if pgid <= 0 {
            return;
        }
        if let Ok(mut guard) = self.managed_pgids.lock() {
            // Prune exited process groups on every registration to bound growth and avoid PGID reuse.
            guard.retain(|&existing| existing == pgid || is_unix_pgid_alive(existing));
            if !guard.contains(&pgid) {
                guard.push(pgid);
            }
        }
        self.sync_unix_pid_file();
    }

    #[cfg(unix)]
    fn sync_unix_pid_file(&self) {
        let Some(ref path) = self.pid_file else {
            return;
        };
        let pgids: Vec<i32> = self
            .managed_pgids
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        if pgids.is_empty() {
            let _ = std::fs::remove_file(path);
            return;
        }
        let body = pgids
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        let _ = AppPaths::atomic_write(path, body.as_bytes());
    }
}

impl Drop for JobGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::Foundation::CloseHandle;
            if !self.job_handle.0.is_null() {
                // SAFETY: Closing the last Job Object handle triggers `KILL_ON_JOB_CLOSE`.
                unsafe {
                    let _ = CloseHandle(self.job_handle.0);
                }
                self.job_handle.0 = std::ptr::null_mut();
            }
        }
        #[cfg(unix)]
        {
            let _ = self.terminate_all();
        }
    }
}

/// Probe whether a Unix process group (`-pgid`) still has at least one live member.
/// Returns `false` when `kill(-pgid, 0)` fails with `ESRCH` (no such process group).
#[cfg(unix)]
fn is_unix_pgid_alive(pgid: i32) -> bool {
    if pgid <= 0 {
        return false;
    }
    // SAFETY: Signal 0 only checks process-group existence without delivering a signal.
    let rc = unsafe { libc::kill(-pgid, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

/// Check whether a running process matches CatCloud's managed core or application binaries
/// (`mihomo` or `catcloud` in process name, executable path, or command-line arguments).
/// Used on Unix before terminating a stale PGID recorded in `core.pid` so OS PID/PGID reuse
/// can never terminate an unrelated system process.
pub fn is_managed_stale_process(
    name: &str,
    exe_path: Option<&Path>,
    cmdline: &[String],
) -> bool {
    let matches_token = |text: &str| {
        let lower = text.to_ascii_lowercase();
        lower.contains("mihomo") || lower.contains("catcloud")
    };
    if matches_token(name) {
        return true;
    }
    if let Some(exe) = exe_path {
        if matches_token(&exe.to_string_lossy()) {
            return true;
        }
    }
    cmdline.iter().any(|arg| matches_token(arg))
}

/// Clean up stale child process groups recorded in a Unix/macOS PID file from a crashed prior run.
/// Verifies via `sysinfo::System` that the live process(es) belong to `mihomo` or `catcloud`
/// before delivering `SIGTERM`/`SIGKILL` so PID/PGID reuse never harms unrelated system processes.
#[cfg(unix)]
pub fn cleanup_stale_pid_file(pid_file: &Path) {
    use sysinfo::{Pid, ProcessRefreshKind, RefreshKind, System, UpdateKind};

    let Ok(content) = std::fs::read_to_string(pid_file) else {
        return;
    };

    let my_pid = std::process::id() as i32;
    let candidate_pgids: Vec<i32> = content
        .lines()
        .filter_map(|line| line.trim().parse::<i32>().ok())
        .filter(|&pgid| pgid > 1 && pgid != my_pid)
        .collect();

    if !candidate_pgids.is_empty() {
        let refresh = RefreshKind::nothing().with_processes(
            ProcessRefreshKind::nothing()
                .with_cmd(UpdateKind::Always)
                .with_exe(UpdateKind::Always),
        );
        let system = System::new_with_specifics(refresh);

        for pgid in candidate_pgids {
            if !is_unix_pgid_alive(pgid) {
                continue;
            }

            let verified_managed = if let Some(proc_info) = system.process(Pid::from_u32(pgid as u32)) {
                let name = proc_info.name().to_string_lossy();
                let cmdline: Vec<String> = proc_info
                    .cmd()
                    .iter()
                    .map(|arg| arg.to_string_lossy().into_owned())
                    .collect();
                let matched = is_managed_stale_process(&name, proc_info.exe(), &cmdline);
                if !matched {
                    tracing::warn!(
                        pgid,
                        process = %name,
                        "skipping stale pid cleanup: PID appears reused by unrelated process"
                    );
                }
                matched
            } else {
                // Leader exited; check whether any surviving member of `-pgid` is a managed process
                // and no unrelated process occupies the group.
                let mut found_managed = false;
                let mut found_unrelated = false;
                for (pid, proc_info) in system.processes() {
                    let raw_pid = pid.as_u32() as i32;
                    if raw_pid <= 1 || raw_pid == my_pid {
                        continue;
                    }
                    // SAFETY: `getpgid` is a read-only POSIX query for the target process's PGID.
                    let member_pgid = unsafe { libc::getpgid(raw_pid) };
                    if member_pgid == pgid {
                        let name = proc_info.name().to_string_lossy();
                        let cmdline: Vec<String> = proc_info
                            .cmd()
                            .iter()
                            .map(|arg| arg.to_string_lossy().into_owned())
                            .collect();
                        if is_managed_stale_process(&name, proc_info.exe(), &cmdline) {
                            found_managed = true;
                        } else {
                            found_unrelated = true;
                            tracing::warn!(
                                pgid,
                                member_pid = raw_pid,
                                process = %name,
                                "skipping stale pgid cleanup: unrelated process found in process group"
                            );
                            break;
                        }
                    }
                }
                found_managed && !found_unrelated
            };

            if verified_managed {
                // SAFETY: Terminating verified stale managed process group recorded by prior instance.
                unsafe {
                    let _ = libc::kill(-pgid, libc::SIGTERM);
                }
                std::thread::sleep(Duration::from_millis(80));
                if is_unix_pgid_alive(pgid) {
                    // SAFETY: Escalating to SIGKILL for verified managed process group still alive.
                    unsafe {
                        let _ = libc::kill(-pgid, libc::SIGKILL);
                    }
                }
            }
        }
    }
    let _ = std::fs::remove_file(pid_file);
}

// ============================================================================
// Host Job Object inspection & 3-branch escape self-restart (`spawn_detached_self`)
// ============================================================================

/// Inspect whether the current process is enclosed in a Windows Job Object and whether
/// `KILL_ON_JOB_CLOSE` / `BREAKAWAY_OK` flags are active.
pub fn inspect_current_job_limits() -> JobLimitInfo {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::System::JobObjects::{
            IsProcessInJob, JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK, JOBOBJECT_BASIC_LIMIT_INFORMATION,
            JobObjectBasicLimitInformation, QueryInformationJobObject,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        let mut in_job: i32 = 0;
        // SAFETY: Querying membership of the current process pseudo-handle in any Job Object.
        let ok = unsafe { IsProcessInJob(GetCurrentProcess(), std::ptr::null_mut(), &mut in_job) };
        if ok == 0 {
            return JobLimitInfo {
                in_job: false,
                kill_on_close: false,
                breakaway_ok: false,
                query_failed: true,
            };
        }
        if in_job == 0 {
            return JobLimitInfo::default();
        }

        let mut info: JOBOBJECT_BASIC_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        let mut ret_len: u32 = 0;
        // SAFETY: Passing NULL job handle queries the job object associated with the current process.
        let q_ok = unsafe {
            QueryInformationJobObject(
                std::ptr::null_mut(),
                JobObjectBasicLimitInformation,
                (&mut info as *mut JOBOBJECT_BASIC_LIMIT_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_BASIC_LIMIT_INFORMATION>() as u32,
                &mut ret_len,
            )
        };
        if q_ok == 0 {
            return JobLimitInfo {
                in_job: true,
                kill_on_close: true,
                breakaway_ok: false,
                query_failed: true,
            };
        }

        let flags = info.LimitFlags;
        let kill_on_close = (flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) != 0;
        let breakaway_ok = (flags
            & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK))
            != 0;
        JobLimitInfo {
            in_job: true,
            kill_on_close,
            breakaway_ok,
            query_failed: false,
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        JobLimitInfo::default()
    }
}

/// Spawn a detached process (typically a restarted copy of CatCloud itself) that will survive
/// even if the current process is inside a strict `KILL_ON_JOB_CLOSE` host Job Object.
///
/// Windows 3-branch detachment logic:
/// 1. Not in a `KILL_ON_JOB_CLOSE` Job -> direct detached `Command::spawn`.
/// 2. In a Job with `BREAKAWAY_OK` -> `CREATE_BREAKAWAY_FROM_JOB` (falls back to #3 on error).
/// 3. In a strict non-breakaway Job -> `Invoke-CimMethod Win32_Process Create` via WMI escape.
pub fn spawn_detached_self(
    exe_path: &Path,
    args: &[String],
    cwd: &Path,
) -> CatResult<DetachedSpawnResult> {
    if !exe_path.exists() {
        return Err(CatError::Validation(format!(
            "detached executable does not exist: {}",
            exe_path.display()
        )));
    }

    #[cfg(target_os = "windows")]
    {
        use std::process::{Command, Stdio};
        use windows_sys::Win32::System::Threading::{
            CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW,
        };

        let base_flags = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP;
        let job_info = inspect_current_job_limits();
        let mut errors: Vec<String> = Vec::new();

        if !job_info.kill_on_close {
            match Command::new(exe_path)
                .args(args)
                .current_dir(cwd)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(base_flags)
                .spawn()
            {
                Ok(child) => {
                    return Ok(DetachedSpawnResult {
                        method: SpawnMethod::Direct,
                        pid: Some(child.id()),
                    });
                }
                Err(e) => errors.push(format!("direct spawn failed: {e}")),
            }
        } else {
            if job_info.breakaway_ok {
                match Command::new(exe_path)
                    .args(args)
                    .current_dir(cwd)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .creation_flags(base_flags | CREATE_BREAKAWAY_FROM_JOB)
                    .spawn()
                {
                    Ok(child) => {
                        return Ok(DetachedSpawnResult {
                            method: SpawnMethod::Breakaway,
                            pid: Some(child.id()),
                        });
                    }
                    Err(e) => errors.push(format!("breakaway spawn failed: {e}")),
                }
            }

            match spawn_via_wmi_windows(exe_path, args, cwd, Duration::from_secs(8)) {
                Ok(pid) => {
                    return Ok(DetachedSpawnResult {
                        method: SpawnMethod::WmiEscape,
                        pid: Some(pid),
                    });
                }
                Err(e) => errors.push(format!("WMI escape failed: {e}")),
            }
        }

        Err(CatError::Process(format!(
            "failed to spawn detached self ({}): {}",
            exe_path.display(),
            errors.join("; ")
        )))
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};

        let mut cmd = Command::new(exe_path);
        cmd.args(args)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: `setsid()` is async-signal-safe and detaches the child into a new session.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd
            .spawn()
            .map_err(|e| CatError::Process(format!("unix detached spawn failed: {e}")))?;
        Ok(DetachedSpawnResult {
            method: SpawnMethod::UnixDetached,
            pid: Some(child.id()),
        })
    }
}

/// Resolve the executable path to relaunch during self-restart.
/// On Linux AppImage launches, prefers a validated existing `$APPIMAGE` path over `/tmp/.mount_*`.
pub fn resolve_restarted_self_exe_path(
    current_exe: &Path,
    is_linux: bool,
    appimage_env: Option<&std::ffi::OsStr>,
) -> PathBuf {
    if is_linux {
        crate::platform::resolve_persistent_linux_exe_path_with_env(current_exe, appimage_env)
    } else {
        current_exe.to_path_buf()
    }
}

/// Convenience helper that relaunches the current executable with `--restarting` prepended
/// (if not already present) using `spawn_detached_self`.
pub fn spawn_restarted_self(extra_args: &[String]) -> CatResult<DetachedSpawnResult> {
    let current_exe = std::env::current_exe()
        .map_err(|e| CatError::Process(format!("cannot determine current_exe: {e}")))?;
    let appimage_env = std::env::var_os("APPIMAGE");
    let exe = resolve_restarted_self_exe_path(
        &current_exe,
        cfg!(target_os = "linux"),
        appimage_env.as_deref(),
    );
    let cwd = exe
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let mut args = Vec::with_capacity(extra_args.len() + 1);
    if !extra_args.iter().any(|a| a == "--restarting") {
        args.push("--restarting".to_string());
    }
    args.extend(extra_args.iter().cloned());
    spawn_detached_self(&exe, &args, &cwd)
}

#[cfg(target_os = "windows")]
#[link(name = "shell32")]
unsafe extern "system" {
    fn ShellExecuteW(
        hwnd: *mut std::ffi::c_void,
        lp_operation: *const u16,
        lp_file: *const u16,
        lp_parameters: *const u16,
        lp_directory: *const u16,
        n_show_cmd: i32,
    ) -> isize;
}

#[cfg(target_os = "windows")]
#[link(name = "ole32")]
unsafe extern "system" {
    fn CoInitializeEx(pv_reserved: *mut std::ffi::c_void, dw_co_init: u32) -> i32;
    fn CoUninitialize();
}

/// Lightweight RAII guard initializing a Win32 STA COM apartment on the current thread
/// before calling `ShellExecuteW`, and uninitializing it on drop only when `hr >= 0`.
#[cfg(target_os = "windows")]
struct ComApartmentGuard {
    should_uninit: bool,
}

#[cfg(target_os = "windows")]
impl ComApartmentGuard {
    fn init_sta() -> Self {
        // COINIT_APARTMENTTHREADED (0x2) | COINIT_DISABLE_OLE1DDE (0x4)
        const COINIT_APARTMENTTHREADED: u32 = 0x2;
        const COINIT_DISABLE_OLE1DDE: u32 = 0x4;
        // SAFETY: Initializes COM apartment for the current thread with valid flags and null reserved pointer.
        let hr = unsafe {
            CoInitializeEx(
                std::ptr::null_mut(),
                COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE,
            )
        };
        Self {
            should_uninit: hr >= 0,
        }
    }
}

#[cfg(target_os = "windows")]
impl Drop for ComApartmentGuard {
    fn drop(&mut self) {
        if self.should_uninit {
            // SAFETY: Paired with a successful (`hr >= 0`) `CoInitializeEx` on this thread.
            unsafe {
                CoUninitialize();
            }
            self.should_uninit = false;
        }
    }
}

/// Relaunch `exe` with Windows UAC elevation (`ShellExecuteW` verb `"runas"`).
///
/// - Returns `Ok(true)` when the elevated process was successfully started.
/// - Returns `Ok(false)` when the user cancelled the UAC prompt (`ERROR_CANCELLED = 1223` or
///   `SE_ERR_ACCESSDENIED = 5`).
/// - Returns `Err(_)` on non-Windows platforms, missing executable, or unexpected OS errors.
pub fn relaunch_self_as_admin(exe: &Path, args: &[String], workdir: &Path) -> CatResult<bool> {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Foundation::GetLastError;

        const SW_SHOWNORMAL: i32 = 1;
        const SE_ERR_ACCESSDENIED: isize = 5;
        const ERROR_CANCELLED_CODE: u32 = 1223;

        if !exe.exists() {
            return Err(CatError::Validation(format!(
                "elevated executable does not exist: {}",
                exe.display()
            )));
        }

        let clean_exe = strip_verbatim_prefix(exe);
        let clean_workdir = strip_verbatim_prefix(workdir);
        let wide_verb = to_wide_null("runas");
        let wide_file = to_wide_null(&clean_exe.to_string_lossy());

        let joined_args = args
            .iter()
            .map(|a| quote_win32_arg(a))
            .collect::<Vec<_>>()
            .join(" ");
        let wide_params = if joined_args.is_empty() {
            None
        } else {
            Some(to_wide_null(&joined_args))
        };
        let workdir_str = clean_workdir.to_string_lossy();
        let wide_dir = if workdir_str.is_empty() {
            None
        } else {
            Some(to_wide_null(&workdir_str))
        };

        let params_ptr = wide_params.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
        let dir_ptr = wide_dir.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());

        let _com_guard = ComApartmentGuard::init_sta();

        // SAFETY: All non-null pointers reference NUL-terminated UTF-16 buffers that outlive this call.
        let rc = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                wide_verb.as_ptr(),
                wide_file.as_ptr(),
                params_ptr,
                dir_ptr,
                SW_SHOWNORMAL,
            )
        };

        if rc > 32 {
            return Ok(true);
        }

        let last_err = unsafe { GetLastError() };
        if last_err == ERROR_CANCELLED_CODE || rc == SE_ERR_ACCESSDENIED {
            return Ok(false);
        }

        Err(CatError::Process(format!(
            "ShellExecuteW(runas, `{}`) failed with rc={rc}, win32_err={last_err}",
            clean_exe.display()
        )))
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = (exe, args, workdir);
        Err(CatError::Process(
            "relaunch_self_as_admin is only supported on Windows".into(),
        ))
    }
}

/// Launch a verified Windows `.exe` or `.msi` installer via `ShellExecuteW`.
///
/// - Returns `Ok(true)` when Windows accepted the launch (`rc > 32`).
/// - Returns `Ok(false)` when the user cancelled elevation (`ERROR_CANCELLED = 1223`,
///   `ERROR_ACCESS_DENIED = 5`, or `SE_ERR_ACCESSDENIED = 5`).
/// - Returns `Err(_)` on non-Windows platforms, missing/non-regular/symlink files,
///   unsupported extensions (anything other than `.exe` / `.msi`), or unexpected launch errors.
pub fn launch_windows_installer(installer_path: &Path) -> CatResult<bool> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Foundation::{GetLastError, SetLastError};

        const SW_SHOWNORMAL: i32 = 1;
        const SE_ERR_ACCESSDENIED: isize = 5;
        const ERROR_ACCESS_DENIED_CODE: u32 = 5;
        const ERROR_CANCELLED_CODE: u32 = 1223;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

        let meta = std::fs::symlink_metadata(installer_path).map_err(|_| {
            CatError::Validation(format!(
                "Windows installer does not exist: {}",
                installer_path.display()
            ))
        })?;
        if meta.file_type().is_symlink()
            || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || !meta.is_file()
        {
            return Err(CatError::Validation(format!(
                "Windows installer path must be an existing regular file: {}",
                installer_path.display()
            )));
        }

        let ext = installer_path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase());
        let is_msi = match ext.as_deref() {
            Some("exe") => false,
            Some("msi") => true,
            _ => {
                return Err(CatError::Validation(format!(
                    "unsupported Windows installer extension (expected .exe or .msi): {}",
                    installer_path.display()
                )));
            }
        };

        let clean_path = strip_verbatim_prefix(installer_path);
        let path_str = clean_path.to_string_lossy();
        if path_str.is_empty() || path_str.contains('\0') {
            return Err(CatError::Validation(
                "Windows installer path is empty or contains NUL characters".into(),
            ));
        }

        let wide_verb = to_wide_null("open");
        let (wide_file, wide_params) = if is_msi {
            let msiexec = windows_msiexec_exe();
            let params = format_msiexec_install_params(&path_str)?;
            (
                to_wide_null(&msiexec.to_string_lossy()),
                Some(to_wide_null(&params)),
            )
        } else {
            (to_wide_null(&path_str), None)
        };

        let parent_dir = clean_path.parent().map(strip_verbatim_prefix);
        let wide_dir = parent_dir
            .as_ref()
            .map(|d| d.to_string_lossy().into_owned())
            .filter(|s| !s.is_empty())
            .map(|s| to_wide_null(&s));

        let params_ptr = wide_params.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
        let dir_ptr = wide_dir.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());

        let _com_guard = ComApartmentGuard::init_sta();

        // SAFETY: Clear any stale Win32 thread error code before ShellExecuteW so a subsequent
        // GetLastError() check cannot misattribute a prior ERROR_CANCELLED. All non-null pointers
        // reference NUL-terminated UTF-16 buffers that outlive this call.
        let rc = unsafe {
            SetLastError(0);
            ShellExecuteW(
                std::ptr::null_mut(),
                wide_verb.as_ptr(),
                wide_file.as_ptr(),
                params_ptr,
                dir_ptr,
                SW_SHOWNORMAL,
            )
        };

        if rc > 32 {
            return Ok(true);
        }

        let last_err = unsafe { GetLastError() };
        if last_err == ERROR_CANCELLED_CODE
            || last_err == ERROR_ACCESS_DENIED_CODE
            || rc == SE_ERR_ACCESSDENIED
        {
            return Ok(false);
        }

        Err(CatError::Process(format!(
            "ShellExecuteW(open, `{}`) failed with rc={rc}, win32_err={last_err}",
            clean_path.display()
        )))
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = installer_path;
        Err(CatError::Validation(
            "launch_windows_installer is only supported on Windows".into(),
        ))
    }
}

#[cfg(any(target_os = "windows", test))]
fn format_msiexec_install_params(path_str: &str) -> CatResult<String> {
    if path_str.is_empty() || path_str.contains('\0') {
        return Err(CatError::Validation(
            "Windows MSI installer path is empty or contains NUL characters".into(),
        ));
    }
    if path_str.contains('"') {
        return Err(CatError::Validation(
            "Windows MSI installer path must not contain double quotes".into(),
        ));
    }
    Ok(format!("/i \"{path_str}\""))
}

#[cfg(target_os = "windows")]
fn windows_msiexec_exe() -> PathBuf {
    if let Ok(root) = std::env::var("SystemRoot") {
        let candidate = PathBuf::from(root).join("System32").join("msiexec.exe");
        if candidate.is_file() {
            return candidate;
        }
    }
    let fallback = PathBuf::from(r"C:\Windows\System32\msiexec.exe");
    if fallback.is_file() {
        return fallback;
    }
    PathBuf::from("msiexec.exe")
}

#[cfg(target_os = "windows")]
const MAX_WMI_OUTPUT_BYTES: usize = 32 * 1024;

#[cfg(target_os = "windows")]
fn read_pipe_bounded<R: std::io::Read>(mut reader: R, max_bytes: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(max_bytes.min(4096));
    let mut chunk = [0u8; 2048];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if out.len() < max_bytes {
                    let take = (max_bytes - out.len()).min(n);
                    out.extend_from_slice(&chunk[..take]);
                }
            }
        }
    }
    out
}

#[cfg(target_os = "windows")]
fn spawn_via_wmi_windows(
    exe_path: &Path,
    args: &[String],
    cwd: &Path,
    timeout: Duration,
) -> CatResult<u32> {
    use std::process::{Command, Stdio};
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

    let cmdline = format_win32_cmdline(exe_path, args);
    let cwd_str = strip_verbatim_prefix(cwd);
    let ps_script = format!(
        "$ProgressPreference = 'SilentlyContinue'\n\
         $ErrorActionPreference = 'Stop'\n\
         $si = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly -Property @{{ ShowWindow = [uint16]0 }}\n\
         $r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{{ CommandLine = {cmd}; CurrentDirectory = {dir}; ProcessStartupInformation = $si }}\n\
         Write-Output \"RV=$($r.ReturnValue);PID=$($r.ProcessId)\"\n",
        cmd = ps_quote(&cmdline),
        dir = ps_quote(&cwd_str.to_string_lossy()),
    );

    let mut utf16_bytes = Vec::with_capacity(ps_script.len() * 2);
    for unit in ps_script.encode_utf16() {
        utf16_bytes.extend_from_slice(&unit.to_le_bytes());
    }
    let encoded = base64::engine::general_purpose::STANDARD.encode(utf16_bytes);

    let ps_exe = windows_powershell_exe();
    let mut child = Command::new(ps_exe)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-EncodedCommand",
            &encoded,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| CatError::Process(format!("failed to start WMI PowerShell helper: {e}")))?;

    // Drain piped stdout/stderr concurrently on background threads (bounded to 32 KiB each)
    // before polling `try_wait` so >4 KiB output can never deadlock the pipe buffer.
    let stdout_handle = child
        .stdout
        .take()
        .map(|out| std::thread::spawn(move || read_pipe_bounded(out, MAX_WMI_OUTPUT_BYTES)));
    let stderr_handle = child
        .stderr
        .take()
        .map(|err| std::thread::spawn(move || read_pipe_bounded(err, MAX_WMI_OUTPUT_BYTES)));

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(CatError::Process(format!(
                        "WMI spawn helper timed out after {:.1}s",
                        timeout.as_secs_f32()
                    )));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CatError::Process(format!("WMI wait error: {e}")));
            }
        }
    };

    let stdout_bytes = stdout_handle
        .and_then(|h| h.join().ok())
        .unwrap_or_default();
    let stderr_bytes = stderr_handle
        .and_then(|h| h.join().ok())
        .unwrap_or_default();
    let stdout_str = String::from_utf8_lossy(&stdout_bytes).into_owned();
    let stderr_str = String::from_utf8_lossy(&stderr_bytes).into_owned();

    if !status.success() {
        let detail = if !stderr_str.trim().is_empty() {
            stderr_str.trim()
        } else {
            stdout_str.trim()
        };
        return Err(CatError::Process(format!(
            "WMI PowerShell helper failed ({status}): {detail}"
        )));
    }

    parse_wmi_create_output(&stdout_str)
}

#[cfg(target_os = "windows")]
fn parse_wmi_create_output(stdout: &str) -> CatResult<u32> {
    let re = regex::Regex::new(r"(?m)^\s*RV=(-?\d+);PID=(\d*)\s*$")
        .map_err(|e| CatError::Process(format!("regex error: {e}")))?;
    let caps = re.captures(stdout).ok_or_else(|| {
        CatError::Process(format!("unexpected WMI output: {}", stdout.trim()))
    })?;
    let rv: i64 = caps[1].parse().unwrap_or(-1);
    let pid: u32 = caps[2].parse().unwrap_or(0);
    if rv != 0 || pid == 0 {
        return Err(CatError::Process(format!(
            "Win32_Process.Create returned RV={rv}, PID={pid}"
        )));
    }
    Ok(pid)
}

#[cfg(target_os = "windows")]
fn format_win32_cmdline(exe_path: &Path, args: &[String]) -> String {
    let clean_exe = strip_verbatim_prefix(exe_path);
    let mut parts = Vec::with_capacity(args.len() + 1);
    parts.push(quote_win32_arg(&clean_exe.to_string_lossy()));
    for arg in args {
        parts.push(quote_win32_arg(arg));
    }
    parts.join(" ")
}

#[cfg(target_os = "windows")]
fn quote_win32_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.chars().any(|c| c == ' ' || c == '\t' || c == '"') {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        if ch == '\\' {
            backslashes += 1;
        } else if ch == '"' {
            for _ in 0..(backslashes * 2 + 1) {
                out.push('\\');
            }
            out.push('"');
            backslashes = 0;
        } else {
            for _ in 0..backslashes {
                out.push('\\');
            }
            backslashes = 0;
            out.push(ch);
        }
    }
    for _ in 0..(backslashes * 2) {
        out.push('\\');
    }
    out.push('"');
    out
}

#[cfg(target_os = "windows")]
fn strip_verbatim_prefix(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        path.to_path_buf()
    }
}

#[cfg(target_os = "windows")]
fn ps_quote(text: &str) -> String {
    let mut out = text.to_string();
    for ch in ['\'', '\u{2018}', '\u{2019}', '\u{201a}', '\u{201b}'] {
        if out.contains(ch) {
            let s = ch.to_string();
            let doubled = format!("{ch}{ch}");
            out = out.replace(&s, &doubled);
        }
    }
    format!("'{out}'")
}

#[cfg(target_os = "windows")]
fn windows_powershell_exe() -> PathBuf {
    if let Ok(root) = std::env::var("SystemRoot") {
        let candidate = PathBuf::from(root)
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        if candidate.is_file() {
            return candidate;
        }
    }
    PathBuf::from("powershell.exe")
}

#[cfg(target_os = "windows")]
fn to_wide_null(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(target_os = "windows")]
#[link(name = "advapi32")]
unsafe extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string_security_descriptor: *const u16,
        string_sd_revision: u32,
        security_descriptor: *mut *mut std::ffi::c_void,
        security_descriptor_size: *mut u32,
    ) -> i32;
    fn GetSecurityInfo(
        handle: windows_sys::Win32::Foundation::HANDLE,
        object_type: u32,
        security_info: u32,
        ppsid_owner: *mut *mut std::ffi::c_void,
        ppsid_group: *mut *mut std::ffi::c_void,
        pp_dacl: *mut *mut std::ffi::c_void,
        pp_sacl: *mut *mut std::ffi::c_void,
        pp_security_descriptor: *mut *mut std::ffi::c_void,
    ) -> u32;
    fn SetSecurityInfo(
        handle: windows_sys::Win32::Foundation::HANDLE,
        object_type: u32,
        security_info: u32,
        psid_owner: *mut std::ffi::c_void,
        psid_group: *mut std::ffi::c_void,
        p_dacl: *mut std::ffi::c_void,
        p_sacl: *mut std::ffi::c_void,
    ) -> u32;
    fn GetSecurityDescriptorSacl(
        p_security_descriptor: *mut std::ffi::c_void,
        lpb_sacl_present: *mut i32,
        p_sacl: *mut *mut std::ffi::c_void,
        lpb_sacl_defaulted: *mut i32,
    ) -> i32;
    fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
        security_descriptor: *mut std::ffi::c_void,
        requested_string_sd_revision: u32,
        security_information: u32,
        string_security_descriptor: *mut *mut u16,
        string_security_descriptor_len: *mut u32,
    ) -> i32;
}

#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(hmem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
}

#[cfg(target_os = "windows")]
struct OwnedSecurityDescriptor(*mut std::ffi::c_void);

#[cfg(target_os = "windows")]
impl OwnedSecurityDescriptor {
    fn from_sddl(sddl: &str) -> Option<Self> {
        const SDDL_REVISION_1: u32 = 1;
        let wide = to_wide_null(sddl);
        let mut sd: *mut std::ffi::c_void = std::ptr::null_mut();
        // SAFETY: Valid NUL-terminated UTF-16 SDDL string and valid output pointer.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok != 0 && !sd.is_null() {
            Some(Self(sd))
        } else {
            None
        }
    }

    fn as_security_attributes(&self) -> windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
        windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>()
                as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }
}

#[cfg(target_os = "windows")]
impl Drop for OwnedSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Allocated by `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
            unsafe {
                let _ = LocalFree(self.0);
            }
            self.0 = std::ptr::null_mut();
        }
    }
}

#[cfg(target_os = "windows")]
const CROSS_IL_SDDL_WITH_ML: &str =
    "D:(A;;GA;;;BA)(A;;GA;;;SY)(A;;0x001F0003;;;AU)S:(ML;;NW;;;ME)";

#[cfg(target_os = "windows")]
const CROSS_IL_SDDL_DACL_ONLY: &str = "D:(A;;GA;;;BA)(A;;GA;;;SY)(A;;0x001F0003;;;AU)";

#[cfg(target_os = "windows")]
fn create_named_mutex_with_cross_il_sd(
    wide_mutex: &[u16],
) -> (windows_sys::Win32::Foundation::HANDLE, u32) {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::Threading::CreateMutexW;

    const ERROR_ACCESS_DENIED_CODE: u32 = 5;

    if let Some(sd) = OwnedSecurityDescriptor::from_sddl(CROSS_IL_SDDL_WITH_ML) {
        let sa = sd.as_security_attributes();
        // SAFETY: Valid SECURITY_ATTRIBUTES and NUL-terminated UTF-16 mutex name.
        let handle = unsafe { CreateMutexW(&sa, 0, wide_mutex.as_ptr()) };
        let last_err = unsafe { GetLastError() };
        if !handle.is_null() {
            return (handle, last_err);
        }
    }

    if let Some(sd) = OwnedSecurityDescriptor::from_sddl(CROSS_IL_SDDL_DACL_ONLY) {
        let sa = sd.as_security_attributes();
        // SAFETY: Valid SECURITY_ATTRIBUTES and NUL-terminated UTF-16 mutex name.
        let handle = unsafe { CreateMutexW(&sa, 0, wide_mutex.as_ptr()) };
        let last_err = unsafe { GetLastError() };
        if !handle.is_null() || last_err == ERROR_ACCESS_DENIED_CODE {
            return (handle, last_err);
        }
    }

    // SAFETY: Fallback to default security descriptor.
    let handle = unsafe { CreateMutexW(std::ptr::null(), 0, wide_mutex.as_ptr()) };
    let last_err = unsafe { GetLastError() };
    (handle, last_err)
}

#[cfg(target_os = "windows")]
fn query_kernel_object_label_sddl(handle: windows_sys::Win32::Foundation::HANDLE) -> Option<String> {
    const SE_KERNEL_OBJECT: u32 = 6;
    const LABEL_SECURITY_INFORMATION: u32 = 0x0000_0010;
    const SDDL_REVISION_1: u32 = 1;

    if handle.is_null() {
        return None;
    }

    let mut sd: *mut std::ffi::c_void = std::ptr::null_mut();
    // SAFETY: Querying mandatory label security info for a live kernel object handle.
    let rc = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            LABEL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != 0 || sd.is_null() {
        return None;
    }

    let mut wide_sddl: *mut u16 = std::ptr::null_mut();
    let mut wide_len: u32 = 0;
    // SAFETY: Converting the returned security descriptor's label SACL to SDDL string.
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            SDDL_REVISION_1,
            LABEL_SECURITY_INFORMATION,
            &mut wide_sddl,
            &mut wide_len,
        )
    };
    let result = if ok != 0 && !wide_sddl.is_null() {
        let mut len = 0usize;
        // SAFETY: `wide_sddl` is a NUL-terminated UTF-16 buffer allocated by Win32.
        unsafe {
            while *wide_sddl.add(len) != 0 {
                len += 1;
            }
            let slice = std::slice::from_raw_parts(wide_sddl, len);
            Some(String::from_utf16_lossy(slice))
        }
    } else {
        None
    };

    unsafe {
        if !wide_sddl.is_null() {
            let _ = LocalFree(wide_sddl.cast());
        }
        let _ = LocalFree(sd);
    }

    result
}

#[cfg(target_os = "windows")]
fn sddl_allows_medium_il_mandatory_label(sddl: &str) -> bool {
    let upper = sddl.to_ascii_uppercase();
    let bytes = upper.as_bytes();

    // Locate the top-level `S:` SACL section (outside parentheses) and slice until the next
    // top-level SDDL section (`O:`, `G:`, `D:`), if any.
    let mut depth = 0usize;
    let mut sacl_start: Option<usize> = None;
    let mut sacl_end = bytes.len();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            b'S' if depth == 0 && sacl_start.is_none() && i + 1 < bytes.len() && bytes[i + 1] == b':' => {
                sacl_start = Some(i + 2);
                i += 2;
                continue;
            }
            b'O' | b'G' | b'D'
                if depth == 0
                    && sacl_start.is_some()
                    && i + 1 < bytes.len()
                    && bytes[i + 1] == b':' =>
            {
                sacl_end = i;
                break;
            }
            _ => {}
        }
        i += 1;
    }

    let Some(start) = sacl_start else {
        return false;
    };
    let sacl_section = &upper[start..sacl_end];

    let mut has_medium_or_low_ml = false;
    let mut ace_start: Option<usize> = None;
    for (idx, ch) in sacl_section.char_indices() {
        match ch {
            '(' => ace_start = Some(idx + 1),
            ')' => {
                if let Some(a_start) = ace_start.take() {
                    let ace = &sacl_section[a_start..idx];
                    let fields: Vec<&str> = ace.split(';').map(str::trim).collect();
                    if fields.len() >= 6 && fields[0] == "ML" {
                        let trustee = fields[5];
                        if matches!(trustee, "HI" | "SI" | "S-1-16-12288" | "S-1-16-16384") {
                            return false;
                        }
                        if matches!(trustee, "ME" | "LW" | "S-1-16-8192" | "S-1-16-4096") {
                            has_medium_or_low_ml = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    has_medium_or_low_ml
}

#[cfg(target_os = "windows")]
fn verify_event_medium_mandatory_label(
    handle: windows_sys::Win32::Foundation::HANDLE,
    event_label: &str,
) -> bool {
    let Some(sddl) = query_kernel_object_label_sddl(handle) else {
        tracing::warn!(
            event = event_label,
            "failed to query mandatory label SDDL on cross-IL named event"
        );
        return false;
    };
    let has_me = sddl_allows_medium_il_mandatory_label(&sddl);
    if !has_me {
        tracing::warn!(
            event = event_label,
            actual_sddl = %sddl,
            "cross-IL named event does not carry a Medium/Low mandatory label (ME/LW); Medium-IL callers may receive ERROR_ACCESS_DENIED"
        );
    }
    has_me
}

#[cfg(target_os = "windows")]
fn repair_event_medium_mandatory_label(
    handle: windows_sys::Win32::Foundation::HANDLE,
    event_label: &str,
) -> bool {
    const SE_KERNEL_OBJECT: u32 = 6;
    const LABEL_SECURITY_INFORMATION: u32 = 0x0000_0010;
    const ML_MEDIUM_SDDL: &str = "S:(ML;;NW;;;ME)";

    if handle.is_null() {
        return false;
    }
    let Some(sd) = OwnedSecurityDescriptor::from_sddl(ML_MEDIUM_SDDL) else {
        tracing::warn!(
            event = event_label,
            "failed to construct S:(ML;;NW;;;ME) security descriptor for mandatory label repair"
        );
        return false;
    };
    let mut sacl_present: i32 = 0;
    let mut sacl_defaulted: i32 = 0;
    let mut p_sacl: *mut std::ffi::c_void = std::ptr::null_mut();
    // SAFETY: `sd.0` is a valid Win32 security descriptor kept alive until after `SetSecurityInfo`.
    let got_sacl = unsafe {
        GetSecurityDescriptorSacl(sd.0, &mut sacl_present, &mut p_sacl, &mut sacl_defaulted)
    };
    if got_sacl == 0 || sacl_present == 0 || p_sacl.is_null() {
        tracing::warn!(
            event = event_label,
            "failed to extract SACL from S:(ML;;NW;;;ME) security descriptor"
        );
        return false;
    }
    // SAFETY: Applies only `LABEL_SECURITY_INFORMATION` onto a valid kernel event handle while
    // `sd` (backing `p_sacl`) remains alive.
    let rc = unsafe {
        SetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            LABEL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            p_sacl,
        )
    };
    drop(sd);
    if rc != 0 {
        tracing::warn!(
            event = event_label,
            win32_err = rc,
            "SetSecurityInfo(LABEL_SECURITY_INFORMATION) failed while repairing cross-IL named event mandatory label"
        );
        return false;
    }
    let verified = verify_event_medium_mandatory_label(handle, event_label);
    if verified {
        tracing::info!(
            event = event_label,
            "repaired cross-IL named event mandatory label to S:(ML;;NW;;;ME)"
        );
    } else {
        tracing::warn!(
            event = event_label,
            "mandatory label re-verification still failed after SetSecurityInfo repair"
        );
    }
    verified
}

#[cfg(target_os = "windows")]
fn finalize_created_named_event(
    ev: windows_sys::Win32::Foundation::HANDLE,
    last_err: u32,
    event_label: &str,
    strict_ml_check: bool,
    sd_variant: &str,
) {
    use windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS;
    use windows_sys::Win32::System::Threading::ResetEvent;

    if last_err == ERROR_ALREADY_EXISTS {
        tracing::warn!(
            event = event_label,
            sd_variant = sd_variant,
            "CreateEventW opened existing named event (ERROR_ALREADY_EXISTS); OS preserved prior security descriptor"
        );
        // Clear any stale pre-existing signaled state before attaching listeners.
        unsafe {
            let _ = ResetEvent(ev);
        }
    }
    if strict_ml_check && !verify_event_medium_mandatory_label(ev, event_label) {
        let _ = repair_event_medium_mandatory_label(ev, event_label);
    }
}

#[cfg(target_os = "windows")]
fn create_named_event_with_cross_il_sd(
    wide_event: &[u16],
    event_label: &str,
    strict_ml_check: bool,
) -> windows_sys::Win32::Foundation::HANDLE {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::Threading::CreateEventW;

    if let Some(sd) = OwnedSecurityDescriptor::from_sddl(CROSS_IL_SDDL_WITH_ML) {
        let sa = sd.as_security_attributes();
        // SAFETY: Valid SECURITY_ATTRIBUTES and NUL-terminated UTF-16 event name.
        let ev = unsafe { CreateEventW(&sa, 0, 0, wide_event.as_ptr()) };
        let last_err = unsafe { GetLastError() };
        if !ev.is_null() {
            finalize_created_named_event(ev, last_err, event_label, strict_ml_check, "with_ml");
            return ev;
        }
        tracing::warn!(
            event = event_label,
            win32_err = last_err,
            "CreateEventW with S:(ML;;NW;;;ME) failed; falling back to DACL-only SDDL"
        );
    } else if strict_ml_check {
        tracing::warn!(
            event = event_label,
            "failed to parse CROSS_IL_SDDL_WITH_ML; falling back to DACL-only SDDL"
        );
    }

    if let Some(sd) = OwnedSecurityDescriptor::from_sddl(CROSS_IL_SDDL_DACL_ONLY) {
        let sa = sd.as_security_attributes();
        // SAFETY: Valid SECURITY_ATTRIBUTES and NUL-terminated UTF-16 event name.
        let ev = unsafe { CreateEventW(&sa, 0, 0, wide_event.as_ptr()) };
        let last_err = unsafe { GetLastError() };
        if !ev.is_null() {
            finalize_created_named_event(ev, last_err, event_label, strict_ml_check, "dacl_only");
            return ev;
        }
    }

    // SAFETY: Fallback to default security descriptor.
    let ev = unsafe { CreateEventW(std::ptr::null(), 0, 0, wide_event.as_ptr()) };
    if !ev.is_null() {
        let last_err = unsafe { GetLastError() };
        finalize_created_named_event(ev, last_err, event_label, strict_ml_check, "default_sd");
    }
    ev
}

#[cfg(target_os = "windows")]
fn signal_named_event(wide_event: &[u16]) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{EVENT_MODIFY_STATE, OpenEventW, SetEvent};

    // SAFETY: Opening existing named event with EVENT_MODIFY_STATE only.
    unsafe {
        let ev = OpenEventW(EVENT_MODIFY_STATE, 0, wide_event.as_ptr());
        if !ev.is_null() {
            let ok = SetEvent(ev) != 0;
            let _ = CloseHandle(ev);
            return ok;
        }
    }
    false
}

#[cfg(target_os = "windows")]
fn signal_existing_wakeup_event(wide_event: &[u16]) {
    let _ = signal_named_event(wide_event);
}

fn config_reload_run_dir(data_dir: &Path) -> PathBuf {
    let canonical = crate::paths::normalize_os_path(
        &std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf()),
    );
    canonical.join("run")
}

fn now_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[cfg(unix)]
fn is_unix_primary_instance_alive(run_dir: &Path) -> bool {
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;

    let lock_path = run_dir.join("instance.lock");
    let Ok(file) = OpenOptions::new().read(true).write(true).open(&lock_path) else {
        return false;
    };
    // Probe whether a live primary instance currently holds the exclusive flock.
    // Because BSD flock is per-open-file-description, a fresh open returns EWOULDBLOCK
    // while the lock is held (including from another guard inside the same process), and
    // succeeds with 0 once release() unlocked/closed the descriptor or the process exited.
    // SAFETY: Valid file descriptor owned by `file` for non-blocking advisory flock probe.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        // SAFETY: Immediately release probe lock; no live primary instance holds it.
        unsafe {
            let _ = libc::flock(file.as_raw_fd(), libc::LOCK_UN);
        }
        return false;
    }
    let raw_os = std::io::Error::last_os_error().raw_os_error();
    raw_os == Some(libc::EWOULDBLOCK) || raw_os == Some(libc::EAGAIN)
}

/// Non-destructively probe whether a primary CatCloud instance currently holds the
/// per-`data_dir` single-instance lock without waking or signaling it.
/// - Windows: read-only `OpenMutexW(SYNCHRONIZATION_SYNCHRONIZE, ...)` on `Local\CatCloud_SI_<hash>`.
/// - Unix: non-blocking advisory `flock` probe via `is_unix_primary_instance_alive`.
pub fn is_primary_instance_alive(data_dir: &Path) -> bool {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
        use windows_sys::Win32::System::Threading::{OpenMutexW, SYNCHRONIZATION_SYNCHRONIZE};

        const ERROR_ACCESS_DENIED_CODE: u32 = 5;

        let instance_hash = compute_instance_hash_readonly(data_dir);
        let mutex_name = format!("Local\\CatCloud_SI_{instance_hash}");
        let wide_mutex = to_wide_null(&mutex_name);
        // SAFETY: Read-only OpenMutexW probe with NUL-terminated UTF-16 mutex name.
        let handle = unsafe { OpenMutexW(SYNCHRONIZATION_SYNCHRONIZE, 0, wide_mutex.as_ptr()) };
        if !handle.is_null() {
            // SAFETY: Valid kernel handle returned by OpenMutexW.
            unsafe {
                let _ = CloseHandle(handle);
            }
            return true;
        }
        unsafe { GetLastError() == ERROR_ACCESS_DENIED_CODE }
    }

    #[cfg(unix)]
    {
        let run_dir = config_reload_run_dir(data_dir);
        is_unix_primary_instance_alive(&run_dir)
    }
}

/// Trigger deterministic cross-IL graceful shutdown for the running instance scoped to `data_dir`.
/// Returns `true` if a live listener event/signal was found and signaled, `false` otherwise.
pub fn signal_graceful_exit_for_data_dir(data_dir: &Path) -> bool {
    #[cfg(target_os = "windows")]
    {
        let instance_hash = compute_instance_hash_readonly(data_dir);
        let event_name = graceful_exit_event_name_for_hash(&instance_hash);
        let wide = to_wide_null(&event_name);
        signal_named_event(&wide)
    }

    #[cfg(unix)]
    {
        let run_dir = config_reload_run_dir(data_dir);
        if !is_unix_primary_instance_alive(&run_dir) {
            return false;
        }
        let signal_path = run_dir.join("graceful_exit.signal");
        std::fs::write(&signal_path, format!("{}", std::process::id())).is_ok()
    }
}

/// Trigger deterministic cross-IL graceful shutdown for the standard installed CatCloud instance
/// (`Local\CatCloud_GracefulExit_Installed_v1` on Windows). Never touches portable or sandbox runs.
pub fn signal_graceful_exit_installed() -> bool {
    #[cfg(target_os = "windows")]
    {
        let wide = to_wide_null(INSTALLED_GRACEFUL_EXIT_EVENT_NAME);
        signal_named_event(&wide)
    }

    #[cfg(unix)]
    {
        let std_dir = AppPaths::standard_os_data_dir();
        signal_graceful_exit_for_data_dir(&std_dir)
    }
}

/// Trigger deterministic cross-IL config hot-reload for the running instance scoped to `data_dir`.
/// Returns `true` if a live listener event/signal was found and signaled, `false` otherwise.
pub fn signal_config_reload_for_data_dir(data_dir: &Path) -> bool {
    #[cfg(target_os = "windows")]
    {
        let instance_hash = compute_instance_hash_readonly(data_dir);
        let event_name = config_reload_event_name_for_hash(&instance_hash);
        let wide = to_wide_null(&event_name);
        signal_named_event(&wide)
    }

    #[cfg(unix)]
    {
        let run_dir = config_reload_run_dir(data_dir);
        if !is_unix_primary_instance_alive(&run_dir) {
            return false;
        }
        let signal_path = run_dir.join("config_reload.signal");
        std::fs::write(&signal_path, format!("{}", std::process::id())).is_ok()
    }
}

/// Atomically persist a cross-process config hot-reload request under `<data_dir>/run/`.
pub fn write_config_reload_request(data_dir: &Path, req: &ConfigReloadRequest) -> CatResult<()> {
    let path = config_reload_run_dir(data_dir).join(CONFIG_RELOAD_REQ_FILE);
    let bytes = serde_json::to_vec_pretty(req)?;
    AppPaths::atomic_write(&path, &bytes)
}

/// Read the latest cross-process config hot-reload request under `<data_dir>/run/` without deleting it.
pub fn read_config_reload_request(data_dir: &Path) -> Option<ConfigReloadRequest> {
    let path = config_reload_run_dir(data_dir).join(CONFIG_RELOAD_REQ_FILE);
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Remove `<data_dir>/run/config_reload_req.json` only when its `req_id` matches `expected_req_id`,
/// preventing a timed-out or expired request's `allow_l3_restart` flag from leaking into a later
/// unrelated reload signal without deleting a newer concurrent request.
pub fn clear_config_reload_request_if_matching(data_dir: &Path, expected_req_id: &str) -> bool {
    let trimmed = expected_req_id.trim();
    if trimmed.is_empty() {
        return false;
    }
    if let Some(existing_req) = read_config_reload_request(data_dir) {
        if existing_req.req_id == trimmed {
            let req_path = config_reload_run_dir(data_dir).join(CONFIG_RELOAD_REQ_FILE);
            return std::fs::remove_file(req_path).is_ok();
        }
    }
    false
}

/// Atomically persist a cross-process config hot-reload acknowledgment under `<data_dir>/run/`.
/// When the on-disk request file carries the same `req_id`, it is cleaned up so subsequent plain
/// write-DB signals cannot accidentally inherit an old `allow_l3_restart` flag.
pub fn write_config_reload_ack(data_dir: &Path, ack: &ConfigReloadAck) -> CatResult<()> {
    let run_dir = config_reload_run_dir(data_dir);
    let path = run_dir.join(CONFIG_RELOAD_ACK_FILE);
    let bytes = serde_json::to_vec_pretty(ack)?;
    // Clear the matching request BEFORE publishing the ack so any reader observing the ack
    // sees a guaranteed happens-before clean request state across all filesystems.
    let _ = clear_config_reload_request_if_matching(data_dir, &ack.req_id);
    AppPaths::atomic_write(&path, &bytes)?;
    Ok(())
}

/// Read the latest cross-process config hot-reload acknowledgment under `<data_dir>/run/`.
pub fn read_config_reload_ack(data_dir: &Path) -> Option<ConfigReloadAck> {
    let path = config_reload_run_dir(data_dir).join(CONFIG_RELOAD_ACK_FILE);
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Write a unique config hot-reload request, signal the running instance for `data_dir`, and
/// poll every 40ms until a matching `ConfigReloadAck` is observed or `timeout` elapses.
///
/// - Returns `NotRunning` (after cleaning the matching request file) if no live instance accepted the signal.
/// - Returns `Ack(ack)` when a matching `ConfigReloadAck` arrives within `timeout`.
/// - Returns `TimedOut { req_id }` if the signal succeeded but no matching ack arrived before `timeout`,
///   cleaning up the matching request file so a stale `allow_l3_restart = true` cannot leak.
pub fn signal_config_reload_and_wait_outcome(
    data_dir: &Path,
    allow_l3_restart: bool,
    timeout: Duration,
) -> ConfigReloadWaitOutcome {
    let created_at_ms = now_unix_millis();
    let seq = CONFIG_RELOAD_REQ_SEQ.fetch_add(1, Ordering::Relaxed);
    let req_id = format!("reload-{}-{created_at_ms}-{seq}", std::process::id());
    let req = ConfigReloadRequest {
        req_id: req_id.clone(),
        allow_l3_restart,
        created_at_ms,
    };
    if write_config_reload_request(data_dir, &req).is_err() {
        return ConfigReloadWaitOutcome::NotRunning;
    }
    if !signal_config_reload_for_data_dir(data_dir) {
        let _ = clear_config_reload_request_if_matching(data_dir, &req_id);
        return ConfigReloadWaitOutcome::NotRunning;
    }

    let deadline = Instant::now() + timeout;
    loop {
        if let Some(ack) = read_config_reload_ack(data_dir) {
            if ack.req_id == req_id {
                return ConfigReloadWaitOutcome::Ack(ack);
            }
        }
        let now = Instant::now();
        if now >= deadline {
            if let Some(ack) = read_config_reload_ack(data_dir) {
                if ack.req_id == req_id {
                    return ConfigReloadWaitOutcome::Ack(ack);
                }
            }
            let _ = clear_config_reload_request_if_matching(data_dir, &req_id);
            return ConfigReloadWaitOutcome::TimedOut { req_id };
        }
        let remaining = deadline.saturating_duration_since(now);
        std::thread::sleep(remaining.min(Duration::from_millis(40)));
    }
}

/// Write a unique config hot-reload request, signal the running instance for `data_dir`, and
/// poll every 40ms until a matching `ConfigReloadAck` is observed or `timeout` elapses.
/// Compatibility wrapper delegating to [`signal_config_reload_and_wait_outcome`].
pub fn signal_config_reload_and_wait(
    data_dir: &Path,
    allow_l3_restart: bool,
    timeout: Duration,
) -> Option<ConfigReloadAck> {
    match signal_config_reload_and_wait_outcome(data_dir, allow_l3_restart, timeout) {
        ConfigReloadWaitOutcome::Ack(ack) => Some(ack),
        ConfigReloadWaitOutcome::NotRunning | ConfigReloadWaitOutcome::TimedOut { .. } => None,
    }
}

// ============================================================================
// SingleInstanceGuard: canonical_data_dir-scoped single instance with wakeup
// ============================================================================

/// Per-`canonical_data_dir` single-instance guard:
/// - Windows: `Local\CatCloud_SI_<instance_hash>` Named Mutex + `Local\CatCloud_Wake_<instance_hash>`
///   Named Event + `Local\CatCloud_GracefulExit_<instance_hash>` Named Event +
///   `Local\CatCloud_ConfigReload_<instance_hash>` Named Event (+ optional
///   `Local\CatCloud_GracefulExit_Installed_v1` for standard installed instances) + dedicated
///   anonymous `stop_event` at `WaitForMultipleObjects` index `0`.
/// - Unix: `<canonical_data_dir>/run/instance.lock` advisory `flock` lock.
///
/// Two instances using different `data_dir` paths (e.g., primary install vs `%TEMP%` E2E sandbox)
/// receive distinct hashes and never block each other.
pub struct SingleInstanceGuard {
    instance_hash: String,
    lock_identifier: String,
    stop_flag: Arc<AtomicBool>,
    listener_thread: Mutex<Option<JoinHandle<()>>>,
    #[cfg(target_os = "windows")]
    mutex_handle: Mutex<Option<SendHandle>>,
    #[cfg(target_os = "windows")]
    stop_event_handle: Mutex<Option<SendHandle>>,
    #[cfg(target_os = "windows")]
    event_handle: Mutex<Option<SendHandle>>,
    #[cfg(target_os = "windows")]
    graceful_exit_event_handle: Mutex<Option<SendHandle>>,
    #[cfg(target_os = "windows")]
    installed_graceful_exit_event_handle: Mutex<Option<SendHandle>>,
    #[cfg(target_os = "windows")]
    config_reload_event_handle: Mutex<Option<SendHandle>>,
    #[cfg(unix)]
    lock_file: Mutex<Option<std::fs::File>>,
    #[cfg(unix)]
    wakeup_signal_path: PathBuf,
    #[cfg(unix)]
    graceful_exit_signal_path: PathBuf,
    #[cfg(unix)]
    config_reload_signal_path: PathBuf,
}

impl std::fmt::Debug for SingleInstanceGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SingleInstanceGuard")
            .field("instance_hash", &self.instance_hash)
            .field("lock_identifier", &self.lock_identifier)
            .finish()
    }
}

impl SingleInstanceGuard {
    /// Acquire the single-instance lock for `paths`.
    /// When `restarting` is true (e.g. `--restarting` CLI flag), waits up to 12 seconds for the
    /// exiting primary instance to release the lock before giving up.
    /// Registers the standard installed graceful-exit event exclusively when
    /// `paths.is_standard_installed_instance()` is `true`.
    pub fn acquire_for_paths(paths: &AppPaths, restarting: bool) -> CatResult<AcquireOutcome> {
        let timeout = if restarting {
            RESTART_WAIT_TIMEOUT
        } else {
            Duration::ZERO
        };
        let register_installed_exit = paths.is_standard_installed_instance();
        Self::acquire_with_options(&paths.root_data_dir, timeout, register_installed_exit)
    }

    /// Acquire the single-instance lock scoped strictly to `canonical_data_dir` without registering
    /// the global installed graceful-exit event.
    pub fn acquire(data_dir: &Path, wait_timeout: Duration) -> CatResult<AcquireOutcome> {
        Self::acquire_with_options(data_dir, wait_timeout, false)
    }

    fn acquire_with_options(
        data_dir: &Path,
        wait_timeout: Duration,
        register_installed_exit: bool,
    ) -> CatResult<AcquireOutcome> {
        let instance_hash = compute_instance_hash(data_dir)?;

        #[cfg(target_os = "windows")]
        {
            Self::acquire_windows(instance_hash, wait_timeout, register_installed_exit)
        }

        #[cfg(unix)]
        {
            let _ = register_installed_exit;
            Self::acquire_unix(data_dir, instance_hash, wait_timeout)
        }
    }

    /// Trigger graceful shutdown for a running instance scoped to `data_dir`.
    pub fn signal_graceful_exit_for_data_dir(data_dir: &Path) -> bool {
        signal_graceful_exit_for_data_dir(data_dir)
    }

    /// Trigger graceful shutdown for the standard installed CatCloud instance.
    pub fn signal_graceful_exit_installed() -> bool {
        signal_graceful_exit_installed()
    }

    /// Trigger live config hot-reload for a running instance scoped to `data_dir`.
    pub fn signal_config_reload_for_data_dir(data_dir: &Path) -> bool {
        signal_config_reload_for_data_dir(data_dir)
    }

    pub fn instance_hash(&self) -> &str {
        &self.instance_hash
    }

    pub fn lock_identifier(&self) -> &str {
        &self.lock_identifier
    }

    #[cfg(target_os = "windows")]
    fn acquire_windows(
        instance_hash: String,
        wait_timeout: Duration,
        register_installed_exit: bool,
    ) -> CatResult<AcquireOutcome> {
        use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError};
        use windows_sys::Win32::System::Threading::CreateEventW;

        const ERROR_ACCESS_DENIED_CODE: u32 = 5;

        let mutex_name = format!("Local\\CatCloud_SI_{instance_hash}");
        let event_name = format!("Local\\CatCloud_Wake_{instance_hash}");
        let graceful_exit_name = graceful_exit_event_name_for_hash(&instance_hash);
        let config_reload_name = config_reload_event_name_for_hash(&instance_hash);
        let wide_mutex = to_wide_null(&mutex_name);
        let wide_event = to_wide_null(&event_name);
        let wide_graceful_exit = to_wide_null(&graceful_exit_name);
        let wide_config_reload = to_wide_null(&config_reload_name);
        let deadline = Instant::now() + wait_timeout;

        loop {
            let (handle, last_err) = create_named_mutex_with_cross_il_sd(&wide_mutex);
            if handle.is_null() {
                if last_err == ERROR_ACCESS_DENIED_CODE {
                    // An elevated (High IL) primary instance already owns this mutex; never return
                    // Err (which would trigger a dual-instance fallback). Respect `--restarting`
                    // wait timeout, otherwise wake the running primary and exit cleanly.
                    if !wait_timeout.is_zero() && Instant::now() < deadline {
                        std::thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    signal_existing_wakeup_event(&wide_event);
                    return Ok(AcquireOutcome::SecondaryWokePrimary);
                }
                return Err(CatError::Process(format!(
                    "CreateMutexW({mutex_name}) failed with Win32 error {last_err}"
                )));
            }

            if last_err != ERROR_ALREADY_EXISTS {
                // Dedicated anonymous manual-reset stop event (always index 0 in WaitForMultipleObjects).
                // SAFETY: Creating an anonymous manual-reset event with default security descriptor.
                let stop_ev = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
                if stop_ev.is_null() {
                    let err = unsafe { GetLastError() };
                    unsafe {
                        let _ = CloseHandle(handle);
                    }
                    return Err(CatError::Process(format!(
                        "CreateEventW(anonymous stop_event) failed with Win32 error {err}"
                    )));
                }

                // Auto-reset wakeup event with cross-IL SD so Medium IL secondary launch can still
                // signal a High IL primary window.
                let wake_ev = create_named_event_with_cross_il_sd(&wide_event, &event_name, false);
                let wake_ev_opt = if wake_ev.is_null() {
                    None
                } else {
                    Some(SendHandle(wake_ev))
                };

                // Per-data_dir cross-IL graceful exit event (strictly checked for S:(ML;;NW;;;ME)).
                let exit_ev = create_named_event_with_cross_il_sd(
                    &wide_graceful_exit,
                    &graceful_exit_name,
                    true,
                );
                let exit_ev_opt = if exit_ev.is_null() {
                    None
                } else {
                    Some(SendHandle(exit_ev))
                };

                // Optional global installed graceful-exit event (only for standard installed instances).
                let installed_exit_opt = if register_installed_exit {
                    let wide_installed = to_wide_null(INSTALLED_GRACEFUL_EXIT_EVENT_NAME);
                    let inst_ev = create_named_event_with_cross_il_sd(
                        &wide_installed,
                        INSTALLED_GRACEFUL_EXIT_EVENT_NAME,
                        true,
                    );
                    if inst_ev.is_null() {
                        None
                    } else {
                        Some(SendHandle(inst_ev))
                    }
                } else {
                    None
                };

                // Per-data_dir cross-IL auto-reset config hot-reload event (strictly checked for S:(ML;;NW;;;ME)).
                let reload_ev = create_named_event_with_cross_il_sd(
                    &wide_config_reload,
                    &config_reload_name,
                    true,
                );
                let reload_ev_opt = if reload_ev.is_null() {
                    None
                } else {
                    Some(SendHandle(reload_ev))
                };

                return Ok(AcquireOutcome::Primary(Self {
                    instance_hash,
                    lock_identifier: mutex_name,
                    stop_flag: Arc::new(AtomicBool::new(false)),
                    listener_thread: Mutex::new(None),
                    mutex_handle: Mutex::new(Some(SendHandle(handle))),
                    stop_event_handle: Mutex::new(Some(SendHandle(stop_ev))),
                    event_handle: Mutex::new(wake_ev_opt),
                    graceful_exit_event_handle: Mutex::new(exit_ev_opt),
                    installed_graceful_exit_event_handle: Mutex::new(installed_exit_opt),
                    config_reload_event_handle: Mutex::new(reload_ev_opt),
                }));
            }

            // Already held by an existing instance: close our duplicate handle first.
            unsafe {
                let _ = CloseHandle(handle);
            }

            if !wait_timeout.is_zero() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }

            signal_existing_wakeup_event(&wide_event);
            return Ok(AcquireOutcome::SecondaryWokePrimary);
        }
    }

    #[cfg(unix)]
    fn acquire_unix(
        data_dir: &Path,
        instance_hash: String,
        wait_timeout: Duration,
    ) -> CatResult<AcquireOutcome> {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::io::AsRawFd;

        let canonical = std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf());
        let run_dir = canonical.join("run");
        std::fs::create_dir_all(&run_dir)?;
        let lock_path = run_dir.join("instance.lock");
        let wakeup_signal_path = run_dir.join("wakeup.signal");
        let graceful_exit_signal_path = run_dir.join("graceful_exit.signal");
        let config_reload_signal_path = run_dir.join("config_reload.signal");
        let deadline = Instant::now() + wait_timeout;

        loop {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&lock_path)?;

            // SAFETY: Valid file descriptor for advisory non-blocking exclusive flock.
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc == 0 {
                let _ = file.set_len(0);
                let _ = write!(file, "{}", std::process::id());
                let _ = file.flush();
                let _ = std::fs::remove_file(&wakeup_signal_path);
                let _ = std::fs::remove_file(&graceful_exit_signal_path);
                let _ = std::fs::remove_file(&config_reload_signal_path);
                return Ok(AcquireOutcome::Primary(Self {
                    instance_hash,
                    lock_identifier: lock_path.to_string_lossy().to_string(),
                    stop_flag: Arc::new(AtomicBool::new(false)),
                    listener_thread: Mutex::new(None),
                    lock_file: Mutex::new(Some(file)),
                    wakeup_signal_path,
                    graceful_exit_signal_path,
                    config_reload_signal_path,
                }));
            }

            let err = std::io::Error::last_os_error();
            let raw_os = err.raw_os_error();
            let would_block = raw_os == Some(libc::EWOULDBLOCK) || raw_os == Some(libc::EAGAIN);
            if !would_block {
                return Err(CatError::Io(err));
            }

            drop(file);
            if !wait_timeout.is_zero() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }

            // Signal primary instance by creating/touching wakeup signal file.
            let _ = std::fs::write(&wakeup_signal_path, format!("{}", std::process::id()));
            return Ok(AcquireOutcome::SecondaryWokePrimary);
        }
    }

    /// Start a background listener that invokes `on_wake` whenever a secondary launch
    /// tries to open the same `data_dir` (compatibility wrapper over [`start_instance_listeners`]).
    pub fn start_wakeup_listener<F>(&self, on_wake: F) -> CatResult<()>
    where
        F: Fn() + Send + 'static,
    {
        self.start_instance_listeners(on_wake, || {})
    }

    /// Start the unified background listener watching both secondary-instance wake signals
    /// (`on_wake`) and deterministic cross-IL graceful shutdown events (`on_graceful_exit`).
    pub fn start_instance_listeners<FW, FE>(&self, on_wake: FW, on_graceful_exit: FE) -> CatResult<()>
    where
        FW: Fn() + Send + 'static,
        FE: Fn() + Send + 'static,
    {
        self.start_instance_listeners_with_reload(on_wake, on_graceful_exit, || {})
    }

    /// Start the unified background listener watching secondary-instance wake signals (`on_wake`),
    /// deterministic cross-IL graceful shutdown events (`on_graceful_exit`), and live config
    /// hot-reload signals (`on_config_reload`).
    ///
    /// On Windows, `WaitForMultipleObjects` always reserves index `0` for the dedicated anonymous
    /// `stop_event` and uses up to 5 handle slots. Receiving `config_reload_event_handle` invokes
    /// `on_config_reload` and keeps listening (never sets `stop_flag` or `break`s). Upon receiving
    /// any graceful-exit event, the listener immediately sets `stop_flag = true`, dispatches
    /// `on_graceful_exit` asynchronously on a detached thread, and immediately `break`s out of the
    /// loop so `RunEvent::Exit -> release() -> join()` can never self-deadlock.
    pub fn start_instance_listeners_with_reload<FW, FE, FR>(
        &self,
        on_wake: FW,
        on_graceful_exit: FE,
        on_config_reload: FR,
    ) -> CatResult<()>
    where
        FW: Fn() + Send + 'static,
        FE: Fn() + Send + 'static,
        FR: Fn() + Send + 'static,
    {
        let mut slot = self
            .listener_thread
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if slot.is_some() {
            return Ok(());
        }

        let stop = Arc::clone(&self.stop_flag);

        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
            use windows_sys::Win32::System::Threading::{INFINITE, WaitForMultipleObjects};

            let stop_addr = {
                let guard = self
                    .stop_event_handle
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                guard.as_ref().map(|h| h.0 as usize)
            };
            let Some(stop_addr) = stop_addr else {
                return Err(CatError::Process(
                    "anonymous stop event handle is not initialized".into(),
                ));
            };

            let wake_addr = {
                let guard = self.event_handle.lock().unwrap_or_else(|e| e.into_inner());
                guard.as_ref().map(|h| h.0 as usize)
            };
            let exit_addr = {
                let guard = self
                    .graceful_exit_event_handle
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                guard.as_ref().map(|h| h.0 as usize)
            };
            let installed_exit_addr = {
                let guard = self
                    .installed_graceful_exit_event_handle
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                guard.as_ref().map(|h| h.0 as usize)
            };
            let reload_addr = {
                let guard = self
                    .config_reload_event_handle
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                guard.as_ref().map(|h| h.0 as usize)
            };

            if wake_addr.is_none()
                && exit_addr.is_none()
                && installed_exit_addr.is_none()
                && reload_addr.is_none()
            {
                return Err(CatError::Process(
                    "no instance listener event handles are initialized".into(),
                ));
            }

            let handle = std::thread::Builder::new()
                .name("catcloud-instance-listener".into())
                .spawn(move || {
                    let mut handles: Vec<windows_sys::Win32::Foundation::HANDLE> =
                        Vec::with_capacity(5);
                    // Index 0 is ALWAYS the dedicated anonymous stop_event.
                    handles.push(stop_addr as windows_sys::Win32::Foundation::HANDLE);

                    let wake_idx = wake_addr.map(|addr| {
                        let idx = handles.len();
                        handles.push(addr as windows_sys::Win32::Foundation::HANDLE);
                        idx
                    });
                    let exit_idx = exit_addr.map(|addr| {
                        let idx = handles.len();
                        handles.push(addr as windows_sys::Win32::Foundation::HANDLE);
                        idx
                    });
                    let installed_exit_idx = installed_exit_addr.map(|addr| {
                        let idx = handles.len();
                        handles.push(addr as windows_sys::Win32::Foundation::HANDLE);
                        idx
                    });
                    let reload_idx = reload_addr.map(|addr| {
                        let idx = handles.len();
                        handles.push(addr as windows_sys::Win32::Foundation::HANDLE);
                        idx
                    });

                    let mut on_graceful_exit = Some(on_graceful_exit);

                    while !stop.load(Ordering::Acquire) {
                        // SAFETY: All event handles stay alive until `release()` joins this thread.
                        let res = unsafe {
                            WaitForMultipleObjects(
                                handles.len() as u32,
                                handles.as_ptr(),
                                0,
                                INFINITE,
                            )
                        };
                        if stop.load(Ordering::Acquire) {
                            break;
                        }
                        let Some(signaled_idx) = res.checked_sub(WAIT_OBJECT_0).map(|v| v as usize)
                        else {
                            break;
                        };
                        if signaled_idx == 0 {
                            // Dedicated stop_event signaled.
                            break;
                        }
                        if Some(signaled_idx) == wake_idx {
                            on_wake();
                        } else if Some(signaled_idx) == reload_idx {
                            // Live Hot-Swap: never stop listener or break; invoke callback and continue waiting.
                            on_config_reload();
                        } else if Some(signaled_idx) == exit_idx
                            || Some(signaled_idx) == installed_exit_idx
                        {
                            // Set stop_flag=true, dispatch callback asynchronously, and break
                            // immediately so RunEvent::Exit -> si.release() -> join() NEVER deadlocks.
                            stop.store(true, Ordering::Release);
                            if let Some(cb) = on_graceful_exit.take() {
                                let spawn_res = std::thread::Builder::new()
                                    .name("catcloud-graceful-exit-dispatch".into())
                                    .spawn(move || {
                                        cb();
                                    });
                                if let Err(err) = spawn_res {
                                    tracing::warn!(
                                        error = %err,
                                        "failed to spawn graceful-exit dispatch thread"
                                    );
                                }
                            }
                            break;
                        } else {
                            break;
                        }
                    }
                })
                .map_err(|e| CatError::Process(format!("failed to spawn instance listener: {e}")))?;

            *slot = Some(handle);
            Ok(())
        }

        #[cfg(unix)]
        {
            let wake_path = self.wakeup_signal_path.clone();
            let exit_path = self.graceful_exit_signal_path.clone();
            let reload_path = self.config_reload_signal_path.clone();
            let handle = std::thread::Builder::new()
                .name("catcloud-instance-listener".into())
                .spawn(move || {
                    let mut on_graceful_exit = Some(on_graceful_exit);
                    while !stop.load(Ordering::Acquire) {
                        // Consume each signal file atomically via `remove_file().is_ok()` to
                        // eliminate the `exists() -> remove_file()` dropped-signal race window.
                        if std::fs::remove_file(&exit_path).is_ok() {
                            if !stop.load(Ordering::Acquire) {
                                stop.store(true, Ordering::Release);
                                if let Some(cb) = on_graceful_exit.take() {
                                    let _ = std::thread::Builder::new()
                                        .name("catcloud-graceful-exit-dispatch".into())
                                        .spawn(move || {
                                            cb();
                                        });
                                }
                            }
                            break;
                        }
                        if std::fs::remove_file(&wake_path).is_ok() {
                            if !stop.load(Ordering::Acquire) {
                                on_wake();
                            }
                        }
                        if std::fs::remove_file(&reload_path).is_ok() {
                            if !stop.load(Ordering::Acquire) {
                                on_config_reload();
                            }
                        }
                        std::thread::sleep(Duration::from_millis(120));
                    }
                })
                .map_err(|e| CatError::Process(format!("failed to spawn instance listener: {e}")))?;

            *slot = Some(handle);
            Ok(())
        }
    }

    /// Immediately break the blocking instance listener wait via the dedicated anonymous
    /// `stop_event` so shutdown releases the single-instance lock in 0ms without touching
    /// wakeup, graceful-exit, or config-reload named events.
    pub fn signal_stop(&self) {
        self.stop_flag.store(true, Ordering::Release);
        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::System::Threading::SetEvent;
            if let Ok(guard) = self.stop_event_handle.lock() {
                if let Some(ref ev) = *guard {
                    if !ev.0.is_null() {
                        // SAFETY: `ev.0` is a live anonymous manual-reset Win32 Event handle.
                        unsafe {
                            let _ = SetEvent(ev.0);
                        }
                    }
                }
            }
        }
    }

    /// Stop any background listener and deterministically close every OS handle owned by this guard.
    pub fn release(&mut self) {
        self.signal_stop();
        if let Ok(mut slot) = self.listener_thread.lock() {
            if let Some(join) = slot.take() {
                let _ = join.join();
            }
        }

        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::Foundation::CloseHandle;
            let close_slot = |slot: &Mutex<Option<SendHandle>>| {
                if let Ok(mut guard) = slot.lock() {
                    if let Some(h) = guard.take() {
                        if !h.0.is_null() {
                            // SAFETY: Listener thread has already joined; safe to close handle.
                            unsafe {
                                let _ = CloseHandle(h.0);
                            }
                        }
                    }
                }
            };
            close_slot(&self.stop_event_handle);
            close_slot(&self.event_handle);
            close_slot(&self.graceful_exit_event_handle);
            close_slot(&self.installed_graceful_exit_event_handle);
            close_slot(&self.config_reload_event_handle);
            close_slot(&self.mutex_handle);
        }

        #[cfg(unix)]
        {
            if let Ok(mut slot) = self.lock_file.lock() {
                if let Some(file) = slot.take() {
                    // Remove all three signal files BEFORE releasing the exclusive flock so a newly
                    // acquiring next instance can never have its fresh signals deleted by us, and
                    // repeated release()/Drop calls after unlock never touch the run directory.
                    let _ = std::fs::remove_file(&self.wakeup_signal_path);
                    let _ = std::fs::remove_file(&self.graceful_exit_signal_path);
                    let _ = std::fs::remove_file(&self.config_reload_signal_path);
                    use std::os::unix::io::AsRawFd;
                    // SAFETY: Unlocking owned file descriptor prior to closing.
                    unsafe {
                        let _ = libc::flock(file.as_raw_fd(), libc::LOCK_UN);
                    }
                    drop(file);
                }
            }
        }
    }
}

impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn make_temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "catcloud-pg-test-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn single_instance_allows_different_data_dirs_to_coexist() {
        let dir_primary = make_temp_dir("primary");
        let dir_sandbox = make_temp_dir("sandbox");

        let g1 = match SingleInstanceGuard::acquire(&dir_primary, Duration::ZERO).unwrap() {
            AcquireOutcome::Primary(g) => g,
            AcquireOutcome::SecondaryWokePrimary => panic!("expected primary for dir_primary"),
        };
        let g2 = match SingleInstanceGuard::acquire(&dir_sandbox, Duration::ZERO).unwrap() {
            AcquireOutcome::Primary(g) => g,
            AcquireOutcome::SecondaryWokePrimary => {
                panic!("different data_dir sandbox must NOT be blocked by primary!")
            }
        };

        assert_ne!(g1.instance_hash(), g2.instance_hash());
        assert_ne!(g1.lock_identifier(), g2.lock_identifier());

        drop(g2);
        drop(g1);
        let _ = std::fs::remove_dir_all(&dir_primary);
        let _ = std::fs::remove_dir_all(&dir_sandbox);
    }

    #[test]
    fn single_instance_blocks_same_data_dir_and_wakes_primary() {
        let dir = make_temp_dir("same-dir");
        let woke_count = Arc::new(AtomicUsize::new(0));
        let woke_clone = Arc::clone(&woke_count);

        let mut primary = match SingleInstanceGuard::acquire(&dir, Duration::ZERO).unwrap() {
            AcquireOutcome::Primary(g) => g,
            AcquireOutcome::SecondaryWokePrimary => panic!("expected primary"),
        };
        primary
            .start_wakeup_listener(move || {
                woke_clone.fetch_add(1, Ordering::SeqCst);
            })
            .unwrap();

        let second = SingleInstanceGuard::acquire(&dir, Duration::ZERO).unwrap();
        assert!(matches!(second, AcquireOutcome::SecondaryWokePrimary));

        let deadline = Instant::now() + Duration::from_secs(2);
        while woke_count.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(woke_count.load(Ordering::SeqCst), 1);

        // signal_stop + release must complete almost instantaneously (well below 200ms).
        let t0 = Instant::now();
        primary.signal_stop();
        primary.release();
        assert!(
            t0.elapsed() < Duration::from_millis(300),
            "release took {:?}",
            t0.elapsed()
        );

        // Now a subsequent acquisition must immediately succeed.
        let third = SingleInstanceGuard::acquire(&dir, Duration::ZERO).unwrap();
        assert!(matches!(third, AcquireOutcome::Primary(_)));

        drop(third);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn single_instance_restarting_wait_acquires_after_release() {
        let dir = make_temp_dir("restart-wait");
        let primary = match SingleInstanceGuard::acquire(&dir, Duration::ZERO).unwrap() {
            AcquireOutcome::Primary(g) => g,
            AcquireOutcome::SecondaryWokePrimary => panic!("expected primary"),
        };

        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(250));
            drop(primary);
        });

        let outcome =
            SingleInstanceGuard::acquire(&dir, Duration::from_secs(3)).expect("acquire with wait");
        releaser.join().unwrap();
        assert!(matches!(outcome, AcquireOutcome::Primary(_)));

        drop(outcome);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn job_guard_kills_assigned_child_within_500ms_on_drop() {
        use std::process::Command;

        let guard = JobGuard::new().expect("create Windows JobGuard");
        let mut cmd = Command::new("cmd.exe");
        cmd.args(["/C", "ping -n 30 127.0.0.1 >nul"]);
        JobGuard::configure_std_command(&mut cmd);

        let mut child = cmd.spawn().expect("spawn sleeper child");
        guard
            .assign_child(&mut child)
            .expect("assign sleeper child to JobGuard");

        // Drop the JobGuard -> KILL_ON_JOB_CLOSE must terminate the child promptly.
        let t0 = Instant::now();
        drop(guard);

        let deadline = Instant::now() + Duration::from_millis(500);
        let mut exited = false;
        while Instant::now() < deadline {
            if child.try_wait().unwrap().is_some() {
                exited = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(15));
        }
        if !exited {
            let _ = child.kill();
            let _ = child.wait();
        }
        assert!(
            exited,
            "JobGuard drop must terminate child within 500ms (elapsed {:?})",
            t0.elapsed()
        );
    }

    #[test]
    fn inspect_job_limits_does_not_panic() {
        let info = inspect_current_job_limits();
        // Simply ensure the call succeeds and produces consistent booleans.
        if !info.in_job {
            assert!(!info.kill_on_close);
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn win32_cmdline_quoting_and_wmi_parser() {
        let cmd = format_win32_cmdline(
            Path::new(r"C:\Program Files\CatCloud\CatCloud.exe"),
            &[
                "--data-dir".into(),
                r"C:\Users\Public\My Data".into(),
                "--restarting".into(),
            ],
        );
        assert!(cmd.starts_with(r#""C:\Program Files\CatCloud\CatCloud.exe""#));
        assert!(cmd.contains(r#""C:\Users\Public\My Data""#));
        assert!(cmd.ends_with("--restarting"));

        assert_eq!(parse_wmi_create_output("RV=0;PID=12345\r\n").unwrap(), 12345);
        assert!(parse_wmi_create_output("RV=2;PID=0\r\n").is_err());

        let big_payload = vec![b'Z'; MAX_WMI_OUTPUT_BYTES + 4096];
        let bounded = read_pipe_bounded(std::io::Cursor::new(big_payload), MAX_WMI_OUTPUT_BYTES);
        assert_eq!(bounded.len(), MAX_WMI_OUTPUT_BYTES);
    }

    #[test]
    fn job_guard_unregister_pid_is_safe_for_missing_and_stale_pids() {
        let guard = JobGuard::new().expect("create JobGuard");
        // Calling unregister_pid with a nonexistent PID must never panic or error.
        guard.unregister_pid(u32::MAX / 2);
    }

    #[test]
    fn relaunch_self_as_admin_rejects_missing_exe_without_prompt() {
        let missing = std::env::temp_dir().join(format!(
            "catcloud-nonexistent-elevated-{}.exe",
            uuid::Uuid::new_v4()
        ));
        let res = relaunch_self_as_admin(&missing, &[], &std::env::temp_dir());
        assert!(res.is_err());
    }

    #[test]
    fn compute_instance_hash_matches_app_paths_instance_hash() {
        let dir = make_temp_dir("hash-align");
        let paths = AppPaths::from_data_dir(dir.clone(), true).expect("init AppPaths");
        let hash = compute_instance_hash(&dir).expect("compute instance hash");
        assert_eq!(hash, paths.instance_hash);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn com_apartment_guard_initializes_and_uninitializes_on_worker_thread() {
        let handle = std::thread::spawn(|| {
            let outer = ComApartmentGuard::init_sta();
            assert!(
                outer.should_uninit,
                "fresh worker thread should initialize STA COM with S_OK"
            );
            let inner = ComApartmentGuard::init_sta();
            assert!(
                inner.should_uninit,
                "re-entrant STA COM init on same thread returns S_FALSE (>= 0) and must pair CoUninitialize"
            );
            drop(inner);
            drop(outer);
        });
        handle.join().expect("worker thread must exit cleanly without COM panic");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn cross_il_sddl_parses_cleanly_for_single_instance_sync_objects() {
        assert!(
            OwnedSecurityDescriptor::from_sddl(CROSS_IL_SDDL_WITH_ML).is_some(),
            "SDDL with Medium mandatory label must parse on Windows"
        );
        assert!(
            OwnedSecurityDescriptor::from_sddl(CROSS_IL_SDDL_DACL_ONLY).is_some(),
            "DACL-only cross-IL SDDL must parse on Windows"
        );
    }

    #[test]
    fn stale_pid_process_identity_guard_matches_only_mihomo_or_catcloud() {
        assert!(is_managed_stale_process("mihomo", None, &[]));
        assert!(is_managed_stale_process(
            "CatCloud-Desktop",
            Some(Path::new("/usr/bin/catcloud-desktop")),
            &[]
        ));
        assert!(is_managed_stale_process(
            "core-runner",
            Some(Path::new("/home/catcloud/.local/share/catcloud/bin/mihomo")),
            &[]
        ));
        assert!(is_managed_stale_process(
            "proxy-core",
            None,
            &[
                "/opt/bin/core".to_string(),
                "-f".to_string(),
                "/home/catcloud/catcloud/runtime.yaml".to_string(),
            ]
        ));

        // Unrelated system or user processes must NEVER be matched on PID/PGID reuse.
        assert!(!is_managed_stale_process(
            "sshd",
            Some(Path::new("/usr/sbin/sshd")),
            &["sshd: root@pts/0".to_string()]
        ));
        assert!(!is_managed_stale_process(
            "systemd",
            Some(Path::new("/lib/systemd/systemd")),
            &["--user".to_string()]
        ));
        assert!(!is_managed_stale_process(
            "bash",
            Some(Path::new("/bin/bash")),
            &["-l".to_string()]
        ));
        assert!(!is_managed_stale_process("", None, &[]));
    }

    #[test]
    fn restarted_self_exe_path_prefers_validated_appimage_on_linux() {
        let mount_exe = Path::new("/tmp/.mount_CatClo9999/usr/bin/catcloud-desktop");
        let tmp_appimage = std::env::temp_dir().join(format!(
            "catcloud-restart-test-{}.AppImage",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&tmp_appimage, b"stub-appimage").unwrap();

        assert_eq!(
            resolve_restarted_self_exe_path(mount_exe, true, Some(tmp_appimage.as_os_str())),
            tmp_appimage
        );
        // Non-Linux platforms must ignore $APPIMAGE and preserve current_exe.
        assert_eq!(
            resolve_restarted_self_exe_path(mount_exe, false, Some(tmp_appimage.as_os_str())),
            mount_exe
        );

        let _ = std::fs::remove_file(&tmp_appimage);
    }

    #[test]
    fn launch_windows_installer_rejects_missing_and_non_installer_paths() {
        let dir = make_temp_dir("win-installer-guard");

        // 1. Missing `.exe` / `.msi` paths must fail without invoking ShellExecuteW.
        let missing_exe = dir.join("missing-setup.exe");
        let err_missing = launch_windows_installer(&missing_exe).unwrap_err();
        assert!(
            matches!(err_missing, CatError::Validation(_)),
            "expected Validation error for missing installer, got {err_missing:?}"
        );

        let missing_msi = dir.join("missing-setup.msi");
        assert!(matches!(
            launch_windows_installer(&missing_msi),
            Err(CatError::Validation(_))
        ));

        // 2. Existing files with disallowed extensions (`.zip`, `.bat`, `.ps1`, `.dmg`, no ext)
        //    must be rejected before any shell invocation.
        for bad_name in [
            "CatCloud-0.2.0-portable.zip",
            "install.bat",
            "install.ps1",
            "CatCloud.dmg",
            "installer_without_ext",
        ] {
            let file_path = dir.join(bad_name);
            std::fs::write(&file_path, b"dummy-payload").unwrap();
            let err = launch_windows_installer(&file_path).unwrap_err();
            assert!(
                matches!(err, CatError::Validation(_)),
                "expected Validation error for '{bad_name}', got {err:?}"
            );
        }

        // 3. A directory disguised with `.exe` suffix must also be rejected.
        let fake_exe_dir = dir.join("disguised.exe");
        std::fs::create_dir_all(&fake_exe_dir).unwrap();
        assert!(matches!(
            launch_windows_installer(&fake_exe_dir),
            Err(CatError::Validation(_))
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn msiexec_install_params_always_quotes_and_rejects_embedded_quotes() {
        // Paths without spaces containing `=` or `;` must still be wrapped in double quotes
        // so msiexec cannot split them as MSI property assignments.
        assert_eq!(
            format_msiexec_install_params(r"C:\Temp\a=b;c\CatCloud-0.2.0.msi").unwrap(),
            r#"/i "C:\Temp\a=b;c\CatCloud-0.2.0.msi""#
        );
        assert_eq!(
            format_msiexec_install_params(r"C:\Program Files\CatCloud\setup.msi").unwrap(),
            r#"/i "C:\Program Files\CatCloud\setup.msi""#
        );
        assert!(matches!(
            format_msiexec_install_params(r#"C:\Temp\evil" /qn.msi"#),
            Err(CatError::Validation(_))
        ));
        assert!(matches!(
            format_msiexec_install_params(""),
            Err(CatError::Validation(_))
        ));
        assert!(matches!(
            format_msiexec_install_params("C:\\Temp\\bad\0.msi"),
            Err(CatError::Validation(_))
        ));
    }

    #[test]
    fn graceful_exit_listener_dispatches_asynchronously_without_release_deadlock_and_isolates_dirs() {
        let dir_a = make_temp_dir("graceful-a");
        let dir_b = make_temp_dir("graceful-b");

        let guard_a = Arc::new(Mutex::new(Some(
            match SingleInstanceGuard::acquire(&dir_a, Duration::ZERO).unwrap() {
                AcquireOutcome::Primary(g) => g,
                AcquireOutcome::SecondaryWokePrimary => panic!("expected primary A"),
            },
        )));
        let mut guard_b = match SingleInstanceGuard::acquire(&dir_b, Duration::ZERO).unwrap() {
            AcquireOutcome::Primary(g) => g,
            AcquireOutcome::SecondaryWokePrimary => panic!("expected primary B"),
        };

        let woke_a = Arc::new(AtomicUsize::new(0));
        let exited_a = Arc::new(AtomicUsize::new(0));
        let exited_b = Arc::new(AtomicUsize::new(0));
        let released_from_cb = Arc::new(AtomicBool::new(false));

        let woke_a_c = Arc::clone(&woke_a);
        let exited_a_c = Arc::clone(&exited_a);
        let guard_a_c = Arc::clone(&guard_a);
        let released_c = Arc::clone(&released_from_cb);

        guard_a
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .start_instance_listeners(
                move || {
                    woke_a_c.fetch_add(1, Ordering::SeqCst);
                },
                move || {
                    exited_a_c.fetch_add(1, Ordering::SeqCst);
                    // Simulate RunEvent::Exit -> si.release() -> join() triggered directly from
                    // the graceful-exit callback: MUST complete without self-deadlocking!
                    if let Some(mut g) = guard_a_c.lock().unwrap().take() {
                        g.release();
                        released_c.store(true, Ordering::SeqCst);
                    }
                },
            )
            .unwrap();

        let exited_b_c = Arc::clone(&exited_b);
        guard_b
            .start_instance_listeners(
                || {},
                move || {
                    exited_b_c.fetch_add(1, Ordering::SeqCst);
                },
            )
            .unwrap();

        // Signaling dir_a MUST wake only dir_a's graceful-exit callback (never wake, never dir_b)
        // and release() inside callback must finish promptly without deadlocking.
        assert!(signal_graceful_exit_for_data_dir(&dir_a));

        let deadline = Instant::now() + Duration::from_secs(2);
        while !released_from_cb.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(15));
        }
        assert_eq!(exited_a.load(Ordering::SeqCst), 1);
        assert!(
            released_from_cb.load(Ordering::SeqCst),
            "release() called from graceful_exit callback must not deadlock"
        );
        assert_eq!(woke_a.load(Ordering::SeqCst), 0);
        assert_eq!(
            exited_b.load(Ordering::SeqCst),
            0,
            "graceful exit for dir_a must NOT touch isolated dir_b"
        );

        // After release(), dir_a's graceful-exit event is closed and lock can be re-acquired cleanly.
        assert!(
            !signal_graceful_exit_for_data_dir(&dir_a),
            "closed graceful-exit handle must no longer be signalable"
        );
        let reacquired = SingleInstanceGuard::acquire(&dir_a, Duration::ZERO).unwrap();
        assert!(matches!(reacquired, AcquireOutcome::Primary(_)));
        drop(reacquired);

        guard_b.release();
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_graceful_exit_event_carries_medium_mandatory_label_and_installed_event_works() {
        let dir = make_temp_dir("installed-ml-check");
        let mut guard = match SingleInstanceGuard::acquire_with_options(&dir, Duration::ZERO, true)
            .unwrap()
        {
            AcquireOutcome::Primary(g) => g,
            AcquireOutcome::SecondaryWokePrimary => panic!("expected primary"),
        };

        // Verify both per-data_dir and installed graceful-exit events carry S:(ML;;NW;;;ME).
        {
            let per_dir_ev = guard.graceful_exit_event_handle.lock().unwrap();
            let h = per_dir_ev.as_ref().expect("per-data_dir graceful exit event").0;
            assert!(
                verify_event_medium_mandatory_label(h, "test-per-dir"),
                "per-data_dir graceful exit event must carry Medium mandatory label"
            );
        }
        {
            let inst_ev = guard.installed_graceful_exit_event_handle.lock().unwrap();
            let h = inst_ev
                .as_ref()
                .expect("installed graceful exit event when register_installed_exit=true")
                .0;
            assert!(
                verify_event_medium_mandatory_label(h, INSTALLED_GRACEFUL_EXIT_EVENT_NAME),
                "installed graceful exit event must carry Medium mandatory label"
            );
        }

        let exited = Arc::new(AtomicUsize::new(0));
        let exited_c = Arc::clone(&exited);
        guard
            .start_instance_listeners(
                || {},
                move || {
                    exited_c.fetch_add(1, Ordering::SeqCst);
                },
            )
            .unwrap();

        assert!(signal_graceful_exit_installed());
        let deadline = Instant::now() + Duration::from_secs(2);
        while exited.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(15));
        }
        assert_eq!(exited.load(Ordering::SeqCst), 1);

        guard.release();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn sddl_medium_mandatory_label_parser_accepts_valid_variants_and_rejects_high_il() {
        assert!(sddl_allows_medium_il_mandatory_label("S:(ML;;NW;;;ME)"));
        assert!(sddl_allows_medium_il_mandatory_label(
            "S:AI(ML;OICI;NW;;;ME)"
        ));
        assert!(sddl_allows_medium_il_mandatory_label(
            "S:(ML;;NWNX;;;S-1-16-8192)"
        ));
        assert!(sddl_allows_medium_il_mandatory_label("S:(ML;;NW;;;LW)"));
        assert!(sddl_allows_medium_il_mandatory_label(
            "D:(A;;GA;;;BA)S:P(ML;;NW;;;S-1-16-4096)"
        ));

        assert!(!sddl_allows_medium_il_mandatory_label("S:(ML;;NW;;;HI)"));
        assert!(!sddl_allows_medium_il_mandatory_label("S:(ML;;NW;;;SI)"));
        assert!(!sddl_allows_medium_il_mandatory_label(
            "S:(ML;;NW;;;S-1-16-12288)"
        ));
        assert!(!sddl_allows_medium_il_mandatory_label(
            "S:(ML;;NW;;;S-1-16-16384)"
        ));
        assert!(!sddl_allows_medium_il_mandatory_label(
            "S:(ML;;NW;;;ME)(ML;;NW;;;HI)"
        ));
        assert!(!sddl_allows_medium_il_mandatory_label("D:(A;;GA;;;BA)"));
        assert!(!sddl_allows_medium_il_mandatory_label("D:(ML;;NW;;;ME)"));
        assert!(!sddl_allows_medium_il_mandatory_label(""));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn create_named_event_repairs_preexisting_event_missing_medium_mandatory_label() {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::CreateEventW;

        let ev_name = format!(
            "Local\\CatCloudRepairMlTest_{}",
            uuid::Uuid::new_v4().simple()
        );
        let wide = to_wide_null(&ev_name);

        // Pre-create the event with DACL-only SDDL (no explicit Medium mandatory label).
        let dacl_sd = OwnedSecurityDescriptor::from_sddl(CROSS_IL_SDDL_DACL_ONLY)
            .expect("parse DACL-only SDDL");
        let sa = dacl_sd.as_security_attributes();
        let pre_ev = unsafe { CreateEventW(&sa, 0, 0, wide.as_ptr()) };
        assert!(!pre_ev.is_null(), "pre-creating named event must succeed");

        // Opening the same name via `create_named_event_with_cross_il_sd` hits ERROR_ALREADY_EXISTS
        // and must actively repair the mandatory label to S:(ML;;NW;;;ME) via SetSecurityInfo.
        let opened_ev = create_named_event_with_cross_il_sd(&wide, &ev_name, true);
        assert!(!opened_ev.is_null());
        assert!(
            verify_event_medium_mandatory_label(opened_ev, &ev_name),
            "pre-existing named event must carry Medium mandatory label after ERROR_ALREADY_EXISTS repair"
        );

        unsafe {
            let _ = CloseHandle(opened_ev);
            let _ = CloseHandle(pre_ev);
        }
    }

    #[test]
    fn config_reload_listener_triggers_repeatedly_without_stopping_and_stops_after_release() {
        let dir_a = make_temp_dir("config-reload-a");
        let dir_b = make_temp_dir("config-reload-b");

        let mut guard_a = match SingleInstanceGuard::acquire(&dir_a, Duration::ZERO).unwrap() {
            AcquireOutcome::Primary(g) => g,
            AcquireOutcome::SecondaryWokePrimary => panic!("expected primary A"),
        };
        let mut guard_b = match SingleInstanceGuard::acquire(&dir_b, Duration::ZERO).unwrap() {
            AcquireOutcome::Primary(g) => g,
            AcquireOutcome::SecondaryWokePrimary => panic!("expected primary B"),
        };

        #[cfg(target_os = "windows")]
        {
            let reload_ev = guard_a.config_reload_event_handle.lock().unwrap();
            let h = reload_ev
                .as_ref()
                .expect("per-data_dir config reload event")
                .0;
            assert!(
                verify_event_medium_mandatory_label(h, "test-config-reload"),
                "per-data_dir config reload event must carry Medium mandatory label"
            );
        }

        let woke_a = Arc::new(AtomicUsize::new(0));
        let exited_a = Arc::new(AtomicUsize::new(0));
        let reload_a = Arc::new(AtomicUsize::new(0));
        let reload_b = Arc::new(AtomicUsize::new(0));

        let woke_a_c = Arc::clone(&woke_a);
        let exited_a_c = Arc::clone(&exited_a);
        let reload_a_c = Arc::clone(&reload_a);
        guard_a
            .start_instance_listeners_with_reload(
                move || {
                    woke_a_c.fetch_add(1, Ordering::SeqCst);
                },
                move || {
                    exited_a_c.fetch_add(1, Ordering::SeqCst);
                },
                move || {
                    reload_a_c.fetch_add(1, Ordering::SeqCst);
                },
            )
            .unwrap();

        let reload_b_c = Arc::clone(&reload_b);
        guard_b
            .start_instance_listeners_with_reload(
                || {},
                || {},
                move || {
                    reload_b_c.fetch_add(1, Ordering::SeqCst);
                },
            )
            .unwrap();

        // Trigger config_reload 3 times sequentially: listener MUST remain alive and keep firing,
        // without triggering wake, graceful_exit, or touching isolated dir_b.
        for expected in 1..=3usize {
            assert!(
                signal_config_reload_for_data_dir(&dir_a),
                "config_reload signal #{expected} must succeed while listener is active"
            );
            let deadline = Instant::now() + Duration::from_secs(2);
            while reload_a.load(Ordering::SeqCst) < expected && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(15));
            }
            assert_eq!(
                reload_a.load(Ordering::SeqCst),
                expected,
                "config_reload callback must fire on trigger #{expected}"
            );
        }
        assert_eq!(woke_a.load(Ordering::SeqCst), 0);
        assert_eq!(exited_a.load(Ordering::SeqCst), 0);
        assert_eq!(
            reload_b.load(Ordering::SeqCst),
            0,
            "config_reload for dir_a must NOT touch isolated dir_b"
        );

        // After release(), dir_a's config_reload signal must return false and lock can be reacquired.
        guard_a.release();
        assert!(
            !signal_config_reload_for_data_dir(&dir_a),
            "released guard must no longer accept config_reload signals"
        );
        let reacquired = SingleInstanceGuard::acquire(&dir_a, Duration::ZERO).unwrap();
        assert!(matches!(reacquired, AcquireOutcome::Primary(_)));
        drop(reacquired);

        guard_b.release();
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
    }

    #[test]
    fn config_reload_request_ack_roundtrip_and_signal_and_wait_flow() {
        let dir = make_temp_dir("config-reload-ack");

        // 1. Direct request/ack atomic persistence roundtrip + matching req_id cleanup.
        let req = ConfigReloadRequest {
            req_id: "req-roundtrip-1".to_string(),
            allow_l3_restart: true,
            created_at_ms: 1_700_000_000_001,
        };
        write_config_reload_request(&dir, &req).expect("write config reload request");
        assert_eq!(read_config_reload_request(&dir), Some(req.clone()));

        let mismatched_ack = ConfigReloadAck {
            req_id: "req-other".to_string(),
            applied: true,
            rejected: false,
            level: Some("l2_hot_reload".to_string()),
            error: None,
            completed_at_ms: 1_700_000_000_005,
        };
        write_config_reload_ack(&dir, &mismatched_ack).expect("write mismatched ack");
        assert_eq!(read_config_reload_ack(&dir), Some(mismatched_ack));
        assert_eq!(
            read_config_reload_request(&dir),
            Some(req.clone()),
            "mismatched ack must not delete a pending newer request"
        );

        let matching_ack = ConfigReloadAck {
            req_id: req.req_id.clone(),
            applied: true,
            rejected: false,
            level: Some("l2_hot_reload".to_string()),
            error: None,
            completed_at_ms: 1_700_000_000_010,
        };
        write_config_reload_ack(&dir, &matching_ack).expect("write matching ack");
        assert_eq!(read_config_reload_ack(&dir), Some(matching_ack));
        assert_eq!(
            read_config_reload_request(&dir),
            None,
            "writing matching ack must clear stale request file"
        );

        // 2. When no live instance is running, signal_config_reload_and_wait returns None and cleans req.
        let offline = signal_config_reload_and_wait(&dir, false, Duration::from_millis(200));
        assert!(offline.is_none());
        assert!(
            !config_reload_run_dir(&dir)
                .join(CONFIG_RELOAD_REQ_FILE)
                .exists(),
            "offline signal_config_reload_and_wait must clean up orphaned request file"
        );

        // 3. With a live listener answering with matching ConfigReloadAck, roundtrip succeeds.
        let mut guard = match SingleInstanceGuard::acquire(&dir, Duration::ZERO).unwrap() {
            AcquireOutcome::Primary(g) => g,
            AcquireOutcome::SecondaryWokePrimary => panic!("expected primary"),
        };
        let observed_allow_l3 = Arc::new(AtomicBool::new(false));
        let observed_c = Arc::clone(&observed_allow_l3);
        let dir_cb = dir.clone();
        guard
            .start_instance_listeners_with_reload(
                || {},
                || {},
                move || {
                    if let Some(pending) = read_config_reload_request(&dir_cb) {
                        observed_c.store(pending.allow_l3_restart, Ordering::SeqCst);
                        let ack = ConfigReloadAck {
                            req_id: pending.req_id,
                            applied: true,
                            rejected: false,
                            level: Some("l2_hot_reload".to_string()),
                            error: None,
                            completed_at_ms: now_unix_millis(),
                        };
                        let _ = write_config_reload_ack(&dir_cb, &ack);
                    }
                },
            )
            .unwrap();

        let live_ack = signal_config_reload_and_wait(&dir, true, Duration::from_secs(2))
            .expect("expected live ConfigReloadAck from running listener");
        assert!(live_ack.applied);
        assert!(!live_ack.rejected);
        assert_eq!(live_ack.level.as_deref(), Some("l2_hot_reload"));
        assert!(live_ack.error.is_none());
        assert!(observed_allow_l3.load(Ordering::SeqCst));
        assert_eq!(
            read_config_reload_request(&dir),
            None,
            "completed reload ack must remove its request file"
        );

        guard.release();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_reload_wait_outcome_cleans_req_on_timeout_and_probes_primary_liveness() {
        let dir = make_temp_dir("config-reload-timeout");

        // 1. Offline: not alive and wait_outcome returns NotRunning without leaving request file.
        assert!(!is_primary_instance_alive(&dir));
        let offline =
            signal_config_reload_and_wait_outcome(&dir, true, Duration::from_millis(120));
        assert_eq!(offline, ConfigReloadWaitOutcome::NotRunning);
        assert_eq!(
            read_config_reload_request(&dir),
            None,
            "NotRunning outcome must not leave stale allow_l3_restart request file"
        );

        // 2. Live primary without ack response: is_primary_instance_alive is true,
        //    wait_outcome returns TimedOut { req_id }, and lingering request file is cleaned up.
        let mut guard = match SingleInstanceGuard::acquire(&dir, Duration::ZERO).unwrap() {
            AcquireOutcome::Primary(g) => g,
            AcquireOutcome::SecondaryWokePrimary => panic!("expected primary"),
        };
        assert!(is_primary_instance_alive(&dir));

        let signaled = Arc::new(AtomicBool::new(false));
        let signaled_c = Arc::clone(&signaled);
        guard
            .start_instance_listeners_with_reload(
                || {},
                || {},
                move || {
                    signaled_c.store(true, Ordering::SeqCst);
                },
            )
            .unwrap();

        let timed_out =
            signal_config_reload_and_wait_outcome(&dir, true, Duration::from_millis(350));
        match timed_out {
            ConfigReloadWaitOutcome::TimedOut { req_id } => {
                assert!(!req_id.is_empty(), "TimedOut outcome must carry req_id");
            }
            other => panic!("expected TimedOut outcome, got {other:?}"),
        }
        let wait_deadline = std::time::Instant::now() + Duration::from_millis(600);
        while !signaled.load(Ordering::SeqCst) && std::time::Instant::now() < wait_deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(signaled.load(Ordering::SeqCst));
        assert_eq!(
            read_config_reload_request(&dir),
            None,
            "TimedOut outcome must delete matching config_reload_req.json to prevent allow_l3_restart leak"
        );

        // 3. Matching cleanup helper must never delete a newer concurrent request with different req_id.
        let newer_req = ConfigReloadRequest {
            req_id: "reload-newer-concurrent".to_string(),
            allow_l3_restart: false,
            created_at_ms: now_unix_millis(),
        };
        write_config_reload_request(&dir, &newer_req).expect("write newer request");
        assert!(!clear_config_reload_request_if_matching(&dir, "reload-old-id"));
        assert_eq!(read_config_reload_request(&dir), Some(newer_req));
        assert!(clear_config_reload_request_if_matching(
            &dir,
            "reload-newer-concurrent"
        ));
        assert_eq!(read_config_reload_request(&dir), None);

        // 4. After release, primary liveness probe returns false cleanly.
        guard.release();
        assert!(!is_primary_instance_alive(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
