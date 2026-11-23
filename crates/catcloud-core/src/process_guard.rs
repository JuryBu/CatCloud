use crate::error::{CatError, CatResult};
use crate::paths::AppPaths;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

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
    let canonical = crate::paths::normalize_os_path(
        &std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf()),
    );
    let mut hasher = Sha256::new();
    hasher.update(canonical.to_string_lossy().to_lowercase().as_bytes());
    let digest = hex::encode(hasher.finalize());
    Ok(digest[..8].to_string())
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
fn create_named_event_with_cross_il_sd(
    wide_event: &[u16],
) -> windows_sys::Win32::Foundation::HANDLE {
    use windows_sys::Win32::System::Threading::CreateEventW;

    if let Some(sd) = OwnedSecurityDescriptor::from_sddl(CROSS_IL_SDDL_WITH_ML) {
        let sa = sd.as_security_attributes();
        // SAFETY: Valid SECURITY_ATTRIBUTES and NUL-terminated UTF-16 event name.
        let ev = unsafe { CreateEventW(&sa, 0, 0, wide_event.as_ptr()) };
        if !ev.is_null() {
            return ev;
        }
    }

    if let Some(sd) = OwnedSecurityDescriptor::from_sddl(CROSS_IL_SDDL_DACL_ONLY) {
        let sa = sd.as_security_attributes();
        // SAFETY: Valid SECURITY_ATTRIBUTES and NUL-terminated UTF-16 event name.
        let ev = unsafe { CreateEventW(&sa, 0, 0, wide_event.as_ptr()) };
        if !ev.is_null() {
            return ev;
        }
    }

    // SAFETY: Fallback to default security descriptor.
    unsafe { CreateEventW(std::ptr::null(), 0, 0, wide_event.as_ptr()) }
}

#[cfg(target_os = "windows")]
fn signal_existing_wakeup_event(wide_event: &[u16]) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{EVENT_MODIFY_STATE, OpenEventW, SetEvent};

    // SAFETY: Opening existing named wakeup event with EVENT_MODIFY_STATE only.
    unsafe {
        let ev = OpenEventW(EVENT_MODIFY_STATE, 0, wide_event.as_ptr());
        if !ev.is_null() {
            let _ = SetEvent(ev);
            let _ = CloseHandle(ev);
        }
    }
}

// ============================================================================
// SingleInstanceGuard: canonical_data_dir-scoped single instance with wakeup
// ============================================================================

/// Per-`canonical_data_dir` single-instance guard:
/// - Windows: `Local\CatCloud_SI_<instance_hash>` Named Mutex + `Local\CatCloud_Wake_<instance_hash>` Named Event.
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
    event_handle: Mutex<Option<SendHandle>>,
    #[cfg(unix)]
    lock_file: Mutex<Option<std::fs::File>>,
    #[cfg(unix)]
    wakeup_signal_path: PathBuf,
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
    pub fn acquire_for_paths(paths: &AppPaths, restarting: bool) -> CatResult<AcquireOutcome> {
        let timeout = if restarting {
            RESTART_WAIT_TIMEOUT
        } else {
            Duration::ZERO
        };
        Self::acquire(&paths.root_data_dir, timeout)
    }

    /// Acquire the single-instance lock scoped strictly to `canonical_data_dir`.
    pub fn acquire(data_dir: &Path, wait_timeout: Duration) -> CatResult<AcquireOutcome> {
        let instance_hash = compute_instance_hash(data_dir)?;

        #[cfg(target_os = "windows")]
        {
            Self::acquire_windows(instance_hash, wait_timeout)
        }

        #[cfg(unix)]
        {
            Self::acquire_unix(data_dir, instance_hash, wait_timeout)
        }
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
    ) -> CatResult<AcquireOutcome> {
        use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS};

        const ERROR_ACCESS_DENIED_CODE: u32 = 5;

        let mutex_name = format!("Local\\CatCloud_SI_{instance_hash}");
        let event_name = format!("Local\\CatCloud_Wake_{instance_hash}");
        let wide_mutex = to_wide_null(&mutex_name);
        let wide_event = to_wide_null(&event_name);
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
                // We are the primary instance; create auto-reset wakeup event with cross-IL SD
                // so a Medium IL secondary launch can still signal a High IL primary window.
                let ev = create_named_event_with_cross_il_sd(&wide_event);
                let ev_opt = if ev.is_null() {
                    None
                } else {
                    Some(SendHandle(ev))
                };
                return Ok(AcquireOutcome::Primary(Self {
                    instance_hash,
                    lock_identifier: mutex_name,
                    stop_flag: Arc::new(AtomicBool::new(false)),
                    listener_thread: Mutex::new(None),
                    mutex_handle: Mutex::new(Some(SendHandle(handle))),
                    event_handle: Mutex::new(ev_opt),
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
                return Ok(AcquireOutcome::Primary(Self {
                    instance_hash,
                    lock_identifier: lock_path.to_string_lossy().to_string(),
                    stop_flag: Arc::new(AtomicBool::new(false)),
                    listener_thread: Mutex::new(None),
                    lock_file: Mutex::new(Some(file)),
                    wakeup_signal_path,
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
    /// tries to open the same `data_dir`.
    pub fn start_wakeup_listener<F>(&self, on_wake: F) -> CatResult<()>
    where
        F: Fn() + Send + 'static,
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
            use windows_sys::Win32::System::Threading::{INFINITE, WaitForSingleObject};

            let ev_raw = {
                let guard = self.event_handle.lock().unwrap_or_else(|e| e.into_inner());
                guard.as_ref().map(|h| h.0 as usize)
            };
            let Some(ev_addr) = ev_raw else {
                return Err(CatError::Process(
                    "wakeup event handle is not initialized".into(),
                ));
            };

            let handle = std::thread::Builder::new()
                .name("catcloud-wakeup-listener".into())
                .spawn(move || {
                    let ev_handle = ev_addr as windows_sys::Win32::Foundation::HANDLE;
                    while !stop.load(Ordering::Acquire) {
                        // SAFETY: `event_handle` stays alive until `release()` joins this thread.
                        let res = unsafe { WaitForSingleObject(ev_handle, INFINITE) };
                        if stop.load(Ordering::Acquire) {
                            break;
                        }
                        if res == WAIT_OBJECT_0 {
                            on_wake();
                        } else {
                            break;
                        }
                    }
                })
                .map_err(|e| CatError::Process(format!("failed to spawn wakeup thread: {e}")))?;

            *slot = Some(handle);
            Ok(())
        }

        #[cfg(unix)]
        {
            let signal_path = self.wakeup_signal_path.clone();
            let handle = std::thread::Builder::new()
                .name("catcloud-wakeup-listener".into())
                .spawn(move || {
                    while !stop.load(Ordering::Acquire) {
                        if signal_path.exists() {
                            let _ = std::fs::remove_file(&signal_path);
                            if !stop.load(Ordering::Acquire) {
                                on_wake();
                            }
                        }
                        std::thread::sleep(Duration::from_millis(120));
                    }
                })
                .map_err(|e| CatError::Process(format!("failed to spawn wakeup thread: {e}")))?;

            *slot = Some(handle);
            Ok(())
        }
    }

    /// Immediately break the blocking wakeup wait (`WaitForSingleObject(INFINITE)`) so shutdown
    /// releases the single-instance lock in 0ms without blocking.
    pub fn signal_stop(&self) {
        self.stop_flag.store(true, Ordering::Release);
        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::System::Threading::SetEvent;
            if let Ok(guard) = self.event_handle.lock() {
                if let Some(ref ev) = *guard {
                    if !ev.0.is_null() {
                        // SAFETY: `ev.0` is a live auto-reset Win32 Event handle.
                        unsafe {
                            let _ = SetEvent(ev.0);
                        }
                    }
                }
            }
        }
    }

    /// Stop any wakeup listener and immediately release the underlying OS lock handles.
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
            if let Ok(mut ev_slot) = self.event_handle.lock() {
                if let Some(ev) = ev_slot.take() {
                    if !ev.0.is_null() {
                        // SAFETY: Listener thread has already joined; safe to close event handle.
                        unsafe {
                            let _ = CloseHandle(ev.0);
                        }
                    }
                }
            }
            if let Ok(mut mtx_slot) = self.mutex_handle.lock() {
                if let Some(mtx) = mtx_slot.take() {
                    if !mtx.0.is_null() {
                        // SAFETY: Closing our owned named mutex handle immediately releases the lock.
                        unsafe {
                            let _ = CloseHandle(mtx.0);
                        }
                    }
                }
            }
        }

        #[cfg(unix)]
        {
            if let Ok(mut slot) = self.lock_file.lock() {
                if let Some(file) = slot.take() {
                    use std::os::unix::io::AsRawFd;
                    // SAFETY: Unlocking owned file descriptor prior to closing.
                    unsafe {
                        let _ = libc::flock(file.as_raw_fd(), libc::LOCK_UN);
                    }
                    drop(file);
                }
            }
            let _ = std::fs::remove_file(&self.wakeup_signal_path);
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
}
