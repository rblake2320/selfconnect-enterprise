"""POC (next-four #3): OS-backed agent containment via a Windows Job Object.

This is the containment the SCFH `ExecGuard` could NOT give (it was explicitly NO-GO):
the OS — not the app — bounds the agent subprocess. We create a Job Object with hard
limits, assign a spawned child to it, prove the OS accounting sees it contained, then
prove KILL_ON_JOB_CLOSE terminates the child the instant the job handle closes.

Limits set (all OS-enforced):
  - ACTIVE_PROCESS = 1        (child cannot spawn helpers/grandchildren)
  - JOB_MEMORY cap            (memory ceiling for the whole job)
  - KILL_ON_JOB_CLOSE         (close the handle -> all members die — no orphans)
  - DIE_ON_UNHANDLED_EXCEPTION

Run:  python experiments/win32_probe/job_sandbox.py
Exit: 0 = PASS (contained + killed on close), 1 = partial, 3 = FAIL/unavailable
"""
from __future__ import annotations

import sys
import time

try:
    import win32api
    import win32con
    import win32job
    import win32process
except Exception as e:  # noqa: BLE001
    print(f"FAIL: pywin32 win32job unavailable: {e}")
    sys.exit(3)

JOB_MEM_CAP = 256 * 1024 * 1024  # 256 MB


def main() -> int:
    job = win32job.CreateJobObject(None, "")  # anonymous job

    info = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
    basic = info["BasicLimitInformation"]
    basic["LimitFlags"] = (
        win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | win32job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | win32job.JOB_OBJECT_LIMIT_JOB_MEMORY
        | win32job.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
    )
    basic["ActiveProcessLimit"] = 1
    info["BasicLimitInformation"] = basic
    info["JobMemoryLimit"] = JOB_MEM_CAP
    win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, info)

    # Spawn a child suspended so it executes zero instructions before job assignment.
    # CREATE_SUSPENDED (0x4) holds the main thread before it runs; we resume it only
    # after AssignProcessToJobObject — closing the race window entirely.
    cmd = "ping -n 30 127.0.0.1"
    startup = win32process.STARTUPINFO()
    hproc, hthread, pid, _tid = win32process.CreateProcess(
        None,                          # lpApplicationName
        cmd,                           # lpCommandLine
        None,                          # lpProcessAttributes
        None,                          # lpThreadAttributes
        False,                         # bInheritHandles
        win32con.CREATE_SUSPENDED,     # dwCreationFlags — child cannot run yet
        None,                          # lpEnvironment
        None,                          # lpCurrentDirectory
        startup,                       # lpStartupInfo
    )
    win32job.AssignProcessToJobObject(job, hproc)   # assign before first instruction
    win32process.ResumeThread(hthread)              # now let it run — fully contained
    win32api.CloseHandle(hthread)

    # Open a second handle for polling/termination so we can safely close hproc
    # before the job handle (required by the CloseHandle ordering below).
    poll_rights = win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_TERMINATE | win32con.SYNCHRONIZE
    hproc_poll = win32api.OpenProcess(poll_rights, False, pid)

    class _ProcProxy:
        """Minimal subprocess.Popen-compatible wrapper around a CreateProcess handle."""
        def __init__(self, poll_handle: int, process_id: int) -> None:
            self._handle = poll_handle
            self.pid = process_id
            self.returncode: int | None = None

        def poll(self) -> int | None:
            if self.returncode is not None:
                return self.returncode
            rc = win32process.GetExitCodeProcess(self._handle)
            if rc != win32con.STILL_ACTIVE:
                self.returncode = rc
                return rc
            return None

        def kill(self) -> None:
            win32api.TerminateProcess(self._handle, 1)

    proc = _ProcProxy(hproc_poll, pid)

    time.sleep(0.4)
    acct = win32job.QueryInformationJobObject(job, win32job.JobObjectBasicAccountingInformation)
    active = acct["ActiveProcesses"]
    alive_before = proc.poll() is None
    print(f"[contained] OS job accounting ActiveProcesses={active}; child pid={proc.pid} alive={alive_before}; "
          f"limits: 1 proc, {JOB_MEM_CAP // (1024*1024)}MB, kill-on-close")

    # Prove KILL_ON_JOB_CLOSE: closing the job handle must terminate the child.
    # hproc is the handle returned by CreateProcess; close it before the job handle
    # so the job's KILL_ON_JOB_CLOSE fires cleanly.  hproc_poll stays open for polling.
    win32api.CloseHandle(hproc)
    win32api.CloseHandle(job)
    killed = False
    for _ in range(20):
        time.sleep(0.1)
        if proc.poll() is not None:
            killed = True
            break
    win32api.CloseHandle(hproc_poll)
    print(f"[kill-on-close] child terminated by OS on job-handle close = {killed} "
          f"(exit={proc.returncode})")

    if not killed:
        print("PARTIAL: child was contained but did not die on job close within 2s.")
        return 1
    if active == 1 and alive_before and killed:
        print("PASS: OS-backed containment — job bounded the agent process and killed it on close.")
        return 0
    print(f"PARTIAL: active={active} alive_before={alive_before} killed={killed}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
