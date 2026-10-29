"""Collect emulator video, DroidBot states, and ART method traces."""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from .state_parser import build_droidbot_semantic_stream, droidbot_has_native_states


try:
    from tqdm import tqdm
except ImportError:  # pragma: no cover - fallback for minimal Python envs
    tqdm = None


# Portable defaults; CLI arguments override environment configuration.
from ..config import DATASET_ROOT, PROJECT_ROOT

APK_DIR = Path(os.getenv("MOIRAE_APK_DIR", str(DATASET_ROOT / "apks")))
VIDEO_OUTPUT_DIR = DATASET_ROOT / "videos" / "droidbot" / "benign"
TRACE_OUTPUT_DIR = DATASET_ROOT / "traces" / "droidbot" / "benign"
XML_OUTPUT_DIR = DATASET_ROOT / "xml_states" / "droidbot" / "benign"
DROIDBOT_ROOT = Path(os.getenv("DROIDBOT_ROOT", str(PROJECT_ROOT / "external" / "droidbot")))
DROIDBOT_ACTION_RUNNER_PATH = Path(__file__).resolve().with_name("action_runner.py")
DROIDBOT_OUTPUT_DIR = DATASET_ROOT / "droidbot_out" / "benign"
# Resolve executable names on PATH while retaining Path arguments throughout the runner.
import shutil
def executable_path(variable, command):
    return Path(os.getenv(variable) or shutil.which(command) or command)
AAPT_PATH = executable_path("ANDROID_AAPT", "aapt")
ADB_PATH = executable_path("ANDROID_ADB", "adb")
EMULATOR_PATH = executable_path("ANDROID_EMULATOR", "emulator")
AVD_NAME = os.getenv("ANDROID_AVD", "")
ADB_DEVICE_WAIT_SECONDS = 240
ANDROID_BOOT_WAIT_SECONDS = 300
RECORD_SECONDS = 120
BIT_RATE = 4_000_000
VIDEO_SIZE = "720x1280"
RESTART_EMULATOR_EVERY = 10
SNAPSHOT_NAME = "clean_snapshot"
DROIDBOT_POLICY = "dfs_greedy"
DROIDBOT_EVENT_INTERVAL_SECONDS = 1
DROIDBOT_EVENT_COUNT = 100000000



class ApkRunError(RuntimeError):
    pass


class ApkRecordResult:
    def __init__(self, success, message, cleanup_ok=True, package_name=None, cleanup_message=""):
        self.success = success
        self.message = message
        self.cleanup_ok = cleanup_ok
        self.package_name = package_name
        self.cleanup_message = cleanup_message


def log(message):
    if tqdm is not None:
        tqdm.write(message)
    else:
        print(message)


def run_cmd(args, timeout=None, capture=True, check=False):
    result = subprocess.run(
        [str(arg) for arg in args],
        capture_output=capture,
        text=True,
        encoding="utf-8",
        errors="ignore",
        timeout=timeout,
    )
    if check and result.returncode != 0:
        stderr = (result.stderr or "").strip()
        stdout = (result.stdout or "").strip()
        detail = stderr or stdout or f"exit code {result.returncode}"
        raise ApkRunError(detail)
    return result


def command_output(result):
    return f"{result.stdout or ''}\n{result.stderr or ''}".strip()


def droidbot_dependency_hint(detail):
    module_to_package = {
        "pkg_resources": "setuptools",
        "networkx": "networkx",
        "androguard": "androguard",
        "PIL": "Pillow",
    }
    missing_modules = sorted(set(re.findall(r"No module named '([^']+)'", detail)))
    packages = []
    for module in missing_modules:
        package = module_to_package.get(module, module)
        if package not in packages:
            packages.append(package)
    if not packages:
        packages = ["setuptools", "networkx", "Pillow", "androguard"]
    return (
        f"Current Python: {sys.executable}. "
        "Install DroidBot dependencies in this same environment, for example: "
        f"python -m pip install {' '.join(packages)}"
    )


def adb_base(adb_path, serial=None):
    args = [adb_path]
    if serial:
        args.extend(["-s", serial])
    return args


def adb_cmd(adb_path, serial, *args, timeout=None, capture=True, check=False):
    return run_cmd(adb_base(adb_path, serial) + list(args), timeout, capture, check)


def validate_file(path, label):
    if not path.exists():
        raise ApkRunError(f"{label} not found: {path}")
    if not path.is_file():
        raise ApkRunError(f"{label} is not a file: {path}")


def validate_directory(path, label):
    if not path.exists():
        raise ApkRunError(f"{label} not found: {path}")
    if not path.is_dir():
        raise ApkRunError(f"{label} is not a directory: {path}")


def droidbot_env(adb_path, droidbot_root):
    env = os.environ.copy()
    env["PATH"] = str(adb_path.parent) + os.pathsep + env.get("PATH", "")
    env["PYTHONPATH"] = str(droidbot_root) + os.pathsep + env.get("PYTHONPATH", "")
    return env


def validate_droidbot(droidbot_root, adb_path):
    validate_directory(droidbot_root, "DroidBot root")
    validate_directory(droidbot_root / "droidbot", "DroidBot package")
    validate_file(DROIDBOT_ACTION_RUNNER_PATH, "DroidBot action runner")
    result = subprocess.run(
        [sys.executable, str(DROIDBOT_ACTION_RUNNER_PATH), "--self-check"],
        cwd=str(droidbot_root),
        env=droidbot_env(adb_path, droidbot_root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
        timeout=30,
    )
    if result.returncode != 0:
        detail = command_output(result)
        hint = droidbot_dependency_hint(detail)
        raise ApkRunError(
            "DroidBot actions-only runner failed to start. Install DroidBot Python dependencies first. "
            f"{hint}. Details: {detail}"
        )


def droidbot_output_path(apk_path, output_root):
    return output_root / apk_path.stem


def tail_file(path, limit=3000):
    if not path.exists():
        return ""
    text = path.read_text(encoding="utf-8", errors="ignore")
    return text[-limit:]


def choose_device(adb_path, requested_serial=None):
    if requested_serial:
        wait_for_device(adb_path, requested_serial)
        return requested_serial

    result = run_cmd([adb_path, "devices"], timeout=20, capture=True, check=True)
    devices = []
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])

    if not devices:
        raise ApkRunError(
            "No Android device/emulator found. Start Android Studio emulator first, "
            "then run this script again."
        )

    for device in devices:
        if device.startswith("emulator-"):
            return device
    return devices[0]


def device_state(adb_path, serial):
    result = run_cmd([adb_path, "devices"], timeout=20, capture=True, check=False)
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[0] == serial:
            return parts[1]
    return ""


def wait_for_device(adb_path, serial, timeout=ADB_DEVICE_WAIT_SECONDS):
    deadline = time.time() + timeout
    last_state = ""
    while time.time() < deadline:
        try:
            last_state = device_state(adb_path, serial)
            if last_state == "device":
                return
        except subprocess.TimeoutExpired:
            last_state = "adb devices timed out"
        time.sleep(3)
    raise ApkRunError(f"Timed out waiting for {serial}. Last adb state: {last_state or 'not listed'}")


def wait_for_boot(adb_path, serial, device_timeout=ADB_DEVICE_WAIT_SECONDS, boot_timeout=ANDROID_BOOT_WAIT_SECONDS):
    wait_for_device(adb_path, serial, timeout=device_timeout)
    deadline = time.time() + boot_timeout
    while time.time() < deadline:
        result = adb_cmd(
            adb_path,
            serial,
            "shell",
            "getprop",
            "sys.boot_completed",
            timeout=10,
            capture=True,
            check=False,
        )
        if result.stdout.strip() == "1":
            time.sleep(3)
            return
        time.sleep(2)
    raise ApkRunError("Timed out waiting for Android system boot.")


def start_emulator(emulator_path, avd_name):
    validate_file(emulator_path, "emulator")
    if not avd_name:
        raise ApkRunError("AVD name is empty; set AVD_NAME or pass --avd-name.")
    subprocess.Popen(
        [
            str(emulator_path),
            "-avd",
            avd_name,
            "-no-snapshot-load",
            "-no-snapshot-save",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def hard_restart_emulator(adb_path, emulator_path, avd_name, serial):
    log("[!] Soft reboot did not come back; killing and starting emulator process...")
    try:
        adb_cmd(adb_path, serial, "emu", "kill", timeout=20, capture=True, check=False)
    except subprocess.TimeoutExpired:
        log("[!] adb emu kill timed out; starting emulator anyway.")
    time.sleep(8)
    start_emulator(emulator_path, avd_name)
    wait_for_boot(adb_path, serial, device_timeout=300, boot_timeout=420)
    log("[+] Emulator recovered after hard restart.")


def restart_emulator(adb_path, serial, emulator_path=None, avd_name=None):
    log("[*] Rebooting emulator to refresh long batch state...")
    soft_reboot_started = True
    try:
        adb_cmd(adb_path, serial, "reboot", timeout=15, capture=True, check=False)
    except subprocess.TimeoutExpired:
        soft_reboot_started = False
        log("[!] adb reboot command timed out; trying hard emulator restart.")

    try:
        if not soft_reboot_started:
            raise ApkRunError("adb reboot command timed out")
        wait_for_boot(adb_path, serial)
        log("[+] Emulator is ready again.")
    except ApkRunError as exc:
        if emulator_path and avd_name and is_emulator_serial(serial):
            log(f"[!] Soft reboot wait failed: {exc}")
            hard_restart_emulator(adb_path, emulator_path, avd_name, serial)
        else:
            raise


def is_emulator_serial(serial):
    return bool(re.fullmatch(r"emulator-\d+", serial or ""))


def adb_emu_cmd(adb_path, serial, *args, timeout=120, check=True):
    if not is_emulator_serial(serial):
        raise ApkRunError(f"Emulator console command requires an emulator serial, got: {serial}")
    return adb_cmd(adb_path, serial, "emu", *args, timeout=timeout, capture=True, check=check)


def save_clean_snapshot(adb_path, serial, snapshot_name):
    if not snapshot_name:
        raise ApkRunError("Snapshot name is empty.")
    log(f"[*] Saving clean emulator snapshot: {snapshot_name}")
    result = adb_emu_cmd(
        adb_path,
        serial,
        "avd",
        "snapshot",
        "save",
        snapshot_name,
        timeout=240,
        check=False,
    )
    output = command_output(result)
    if result.returncode != 0 or "KO:" in output:
        raise ApkRunError(f"Failed to save snapshot {snapshot_name}: {output or result.returncode}")
    wait_for_boot(adb_path, serial)
    log(f"[+] Clean snapshot ready: {snapshot_name}")


def load_clean_snapshot(adb_path, serial, snapshot_name):
    if not snapshot_name:
        raise ApkRunError("Snapshot name is empty.")
    log(f"[*] Restoring clean emulator snapshot: {snapshot_name}")
    result = adb_emu_cmd(
        adb_path,
        serial,
        "avd",
        "snapshot",
        "load",
        snapshot_name,
        timeout=240,
        check=False,
    )
    output = command_output(result)
    if result.returncode != 0 or "KO:" in output:
        raise ApkRunError(f"Failed to load snapshot {snapshot_name}: {output or result.returncode}")
    wait_for_boot(adb_path, serial)
    log(f"[+] Snapshot restored: {snapshot_name}")


def recover_with_wipe_data(adb_path, emulator_path, avd_name, serial):
    if not avd_name:
        raise ApkRunError("--avd-name is required when --recovery-mode wipe-data is used.")
    validate_file(emulator_path, "emulator")

    log(f"[*] Wiping AVD data and restarting emulator: {avd_name}")
    adb_cmd(adb_path, serial, "emu", "kill", timeout=20, capture=True, check=False)
    time.sleep(5)
    subprocess.Popen(
        [
            str(emulator_path),
            "-avd",
            avd_name,
            "-wipe-data",
            "-no-snapshot-load",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    wait_for_boot(adb_path, serial)
    log(f"[+] AVD restarted after wipe-data: {avd_name}")


def recover_clean_state(args, serial):
    if args.recovery_mode == "snapshot":
        load_clean_snapshot(args.adb, serial, args.snapshot_name)
    elif args.recovery_mode == "wipe-data":
        recover_with_wipe_data(args.adb, args.emulator, args.avd_name, serial)
    else:
        raise ApkRunError(f"Unsupported recovery mode: {args.recovery_mode}")


def extract_badging(apk_path, aapt_path):
    validate_file(aapt_path, "aapt")
    result = run_cmd([aapt_path, "dump", "badging", apk_path], timeout=30, capture=True, check=True)
    return result.stdout


def get_package_name_from_badging(badging):
    match = re.search(r"^package: name='([^']+)'", badging, re.MULTILINE)
    if not match:
        raise ApkRunError("Could not parse package name from APK.")
    return match.group(1)


def get_package_name(apk_path, aapt_path):
    badging = extract_badging(apk_path, aapt_path)
    return get_package_name_from_badging(badging)


def get_launchable_activity_from_badging(badging):
    match = re.search(r"^launchable-activity: name='([^']+)'", badging, re.MULTILINE)
    return match.group(1) if match else None


def get_launchable_activity(apk_path, aapt_path):
    badging = extract_badging(apk_path, aapt_path)
    return get_launchable_activity_from_badging(badging)


def remote_video_path(package_name):
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", package_name)
    return f"/sdcard/{safe_name}_dynamic.mp4"


def remote_trace_path(package_name):
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", package_name)
    return f"/data/local/tmp/{safe_name}.trace"


def unlock_emulator(adb_path, serial):
    adb_cmd(adb_path, serial, "shell", "input", "keyevent", "224", timeout=10, capture=True, check=False)
    adb_cmd(adb_path, serial, "shell", "wm", "dismiss-keyguard", timeout=10, capture=True, check=False)
    adb_cmd(adb_path, serial, "shell", "input", "keyevent", "82", timeout=10, capture=True, check=False)


def install_apk(apk_path, package_name, adb_path, serial):
    result = adb_cmd(
        adb_path,
        serial,
        "install",
        "-r",
        "-t",
        "-g",
        apk_path,
        timeout=180,
        capture=True,
        check=False,
    )
    output = command_output(result)
    if result.returncode == 0:
        return

    retryable = (
        "INSTALL_FAILED_ALREADY_EXISTS",
        "INSTALL_FAILED_UPDATE_INCOMPATIBLE",
        "INSTALL_FAILED_VERSION_DOWNGRADE",
    )
    if any(error in output for error in retryable):
        uninstall_package(package_name, adb_path, serial, quiet=True)
        retry = adb_cmd(
            adb_path,
            serial,
            "install",
            "-r",
            "-t",
            "-g",
            apk_path,
            timeout=180,
            capture=True,
            check=False,
        )
        if retry.returncode == 0:
            return
        output = command_output(retry)

    raise ApkRunError(output.strip() or "adb install failed")


def normalize_launchable_component(package_name, launchable_activity):
    if not launchable_activity:
        return None
    if "/" in launchable_activity:
        return launchable_activity
    if launchable_activity.startswith("."):
        launchable_activity = package_name + launchable_activity
    return f"{package_name}/{launchable_activity}"


def start_app(package_name, launchable_activity, adb_path, serial):
    unlock_emulator(adb_path, serial)
    component = normalize_launchable_component(package_name, launchable_activity)
    attempts = []
    if component:
        attempts.append(("am", "start", "-W", "-n", component))
    attempts.append(
        (
            "am",
            "start",
            "-W",
            "-a",
            "android.intent.action.MAIN",
            "-c",
            "android.intent.category.LAUNCHER",
            "-p",
            package_name,
        )
    )

    last_output = ""
    for attempt in attempts:
        result = adb_cmd(adb_path, serial, "shell", *attempt, timeout=30, capture=True, check=False)
        last_output = command_output(result)
        if result.returncode == 0 and "Error:" not in last_output and "Exception" not in last_output:
            time.sleep(2)
            return
    raise ApkRunError(f"Failed to start app {package_name}: {last_output or 'no adb output'}")


def start_screenrecord(remote_path, seconds, bit_rate, video_size, adb_path, serial):
    cmd = adb_base(adb_path, serial) + [
        "shell",
        "screenrecord",
        "--time-limit",
        str(seconds),
        "--bit-rate",
        str(bit_rate),
    ]
    if video_size:
        cmd.extend(["--size", video_size])
    cmd.append(remote_path)

    return subprocess.Popen(
        [str(arg) for arg in cmd],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def droidbot_command(
    apk_path,
    serial,
    seconds,
    droidbot_root,
    output_dir,
    policy,
    event_interval,
    event_count,
    debug_mode=False,
):
    cmd = [
        sys.executable,
        str(DROIDBOT_ACTION_RUNNER_PATH),
        "--apk",
        str(apk_path),
        "--serial",
        serial,
        "--output-dir",
        str(output_dir),
        "--policy",
        policy,
        "--timeout",
        str(seconds),
        "--count",
        str(event_count),
        "--interval",
        str(event_interval),
        "--is-emulator",
    ]
    if debug_mode:
        cmd.append("--debug")
    return cmd


def start_droidbot_process(
    apk_path,
    serial,
    seconds,
    adb_path,
    droidbot_root,
    output_dir,
    policy,
    event_interval,
    event_count,
    debug_mode=False,
):
    output_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = output_dir / "droidbot_stdout.txt"
    stderr_path = output_dir / "droidbot_stderr.txt"
    stdout_file = stdout_path.open("w", encoding="utf-8", errors="ignore")
    stderr_file = stderr_path.open("w", encoding="utf-8", errors="ignore")
    cmd = droidbot_command(
        apk_path=apk_path,
        serial=serial,
        seconds=seconds,
        droidbot_root=droidbot_root,
        output_dir=output_dir,
        policy=policy,
        event_interval=event_interval,
        event_count=event_count,
        debug_mode=debug_mode,
    )
    process = subprocess.Popen(
        cmd,
        cwd=str(droidbot_root),
        env=droidbot_env(adb_path, droidbot_root),
        stdout=stdout_file,
        stderr=stderr_file,
    )
    return process, stdout_file, stderr_file, stdout_path, stderr_path


def wait_for_droidbot(process, stdout_file, stderr_file, stdout_path, stderr_path, seconds):
    try:
        return_code = process.wait(timeout=seconds + 90)
    except subprocess.TimeoutExpired as exc:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
        raise ApkRunError(f"DroidBot timed out: {exc}") from exc
    finally:
        stdout_file.close()
        stderr_file.close()

    if return_code != 0:
        detail = tail_file(stderr_path) or tail_file(stdout_path)
        raise ApkRunError(f"DroidBot failed with exit code {return_code}. {detail}")


def pull_video(remote_path, local_path, adb_path, serial):
    local_path.parent.mkdir(parents=True, exist_ok=True)
    adb_cmd(adb_path, serial, "pull", remote_path, local_path, timeout=120, capture=True, check=True)
    if not local_path.exists() or local_path.stat().st_size == 0:
        raise ApkRunError("Video pull finished, but local file is missing or empty.")


def video_path_for_apk(apk_path, output_dir):
    # Keep local videos named after the APK file: sample.apk -> sample.mp4.
    return output_dir / f"{apk_path.stem}.mp4"


def trace_path_for_apk(apk_path, output_dir):
    # Keep local traces named after the APK file: sample.apk -> sample.trace.
    return output_dir / f"{apk_path.stem}.trace"

def xml_dir_for_apk(apk_path, output_dir):
    return output_dir / apk_path.stem


def xml_complete_for_apk(apk_path, output_dir):
    xml_dir = xml_dir_for_apk(apk_path, output_dir)
    report_path = xml_dir / "xml_semantic_stream.json"
    if not report_path.exists() or report_path.stat().st_size == 0:
        return False
    try:
        report = json.loads(report_path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return False
    return (
        report.get("source") == "droidbot_native_states"
        and report.get("event_source") == "droidbot_native_events"
    )


def wait_for_pid(package_name, adb_path, serial, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = adb_cmd(
            adb_path,
            serial,
            "shell",
            "pidof",
            package_name,
            timeout=10,
            capture=True,
            check=False,
        )
        pids = result.stdout.strip().split()
        if pids:
            return pids[0]
        time.sleep(1)
    raise ApkRunError(f"Process did not start or died immediately: {package_name}")


def start_art_profile(pid, remote_path, adb_path, serial):
    result = adb_cmd(
        adb_path,
        serial,
        "shell",
        "am",
        "profile",
        "start",
        pid,
        remote_path,
        timeout=30,
        capture=True,
        check=False,
    )
    output = command_output(result)
    if result.returncode != 0 or "Error" in output or "Exception" in output:
        raise ApkRunError(output or f"Failed to start ART profiling for pid {pid}")


def stop_art_profile(pid, adb_path, serial):
    return adb_cmd(
        adb_path,
        serial,
        "shell",
        "am",
        "profile",
        "stop",
        pid,
        timeout=30,
        capture=True,
        check=False,
    )


def pull_trace(remote_path, local_path, adb_path, serial):
    local_path.parent.mkdir(parents=True, exist_ok=True)
    adb_cmd(adb_path, serial, "shell", "sync", timeout=30, capture=True, check=False)
    adb_cmd(adb_path, serial, "pull", remote_path, local_path, timeout=120, capture=True, check=True)
    if not local_path.exists() or local_path.stat().st_size == 0:
        raise ApkRunError("Trace pull finished, but local file is missing or empty.")

 
def package_installed(package_name, adb_path, serial):
    result = adb_cmd(
        adb_path,
        serial,
        "shell",
        "pm",
        "path",
        package_name,
        timeout=15,
        capture=True,
        check=False,
    )
    return result.returncode == 0 and "package:" in result.stdout


def parse_active_admins(device_policy_output, package_name):
    admins = set()
    component_patterns = [
        r"ComponentInfo\{(" + re.escape(package_name) + r"/[^}]+)\}",
        r"^\s*(" + re.escape(package_name) + r"/[^\s:]+):",
    ]
    for pattern in component_patterns:
        for match in re.finditer(pattern, device_policy_output, re.MULTILINE):
            admins.add(match.group(1))
    return sorted(admins)


def revoke_active_admins(package_name, adb_path, serial):
    result = adb_cmd(
        adb_path,
        serial,
        "shell",
        "dumpsys",
        "device_policy",
        timeout=20,
        capture=True,
        check=False,
    )
    admins = parse_active_admins(result.stdout, package_name)
    removed = []

    for admin in admins:
        attempts = [
            ("dpm", "remove-active-admin", "--user", "0", admin),
            ("dpm", "remove-active-admin", admin),
        ]
        for attempt in attempts:
            remove_result = adb_cmd(
                adb_path,
                serial,
                "shell",
                *attempt,
                timeout=20,
                capture=True,
                check=False,
            )
            if remove_result.returncode == 0 or "Success" in command_output(remove_result):
                removed.append(admin)
                break
    return removed


def uninstall_package(package_name, adb_path, serial, quiet=False):
    adb_cmd(adb_path, serial, "shell", "am", "force-stop", package_name, timeout=15, capture=True, check=False)
    adb_cmd(adb_path, serial, "shell", "pm", "clear", package_name, timeout=30, capture=True, check=False)
    removed_admins = revoke_active_admins(package_name, adb_path, serial)

    attempts = [
        ("uninstall", package_name),
        ("shell", "pm", "uninstall", "--user", "0", package_name),
        ("shell", "cmd", "package", "uninstall", "--user", "0", package_name),
    ]
    last_output = ""

    for attempt in attempts:
        result = adb_cmd(adb_path, serial, *attempt, timeout=60, capture=True, check=False)
        last_output = command_output(result)
        if result.returncode == 0 or "Success" in last_output:
            if not package_installed(package_name, adb_path, serial):
                return True, "uninstalled"

    if not package_installed(package_name, adb_path, serial):
        return True, "uninstalled"

    admin_text = ""
    if removed_admins:
        admin_text = f" Removed active admins first: {', '.join(removed_admins)}."
    message = (
        f"Package still appears installed after cleanup attempts.{admin_text} "
        f"Last adb output: {last_output or 'no output'}"
    )
    if not quiet:
        log(f"[!] Cleanup warning for {package_name}: {message}")
    return False, message


def cleanup(package_name, remote_path, adb_path, serial, keep_installed=False):
    adb_cmd(adb_path, serial, "shell", "pkill", "-INT", "screenrecord", timeout=10, capture=True, check=False)
    adb_cmd(adb_path, serial, "shell", "am", "force-stop", package_name, timeout=15, capture=True, check=False)
    adb_cmd(adb_path, serial, "shell", "rm", "-f", remote_path, timeout=15, capture=True, check=False)
    if keep_installed:
        return True, "cleanup skipped because --keep-installed is enabled"
    return uninstall_package(package_name, adb_path, serial)


def record_apk(
    apk_path,
    output_dir,
    trace_output_dir,
    xml_output_dir,
    adb_path,
    aapt_path,
    serial,
    seconds,
    bit_rate,
    video_size,
    droidbot_root,
    droidbot_output_dir,
    droidbot_policy,
    droidbot_event_interval,
    droidbot_event_count,
    droidbot_debug,
    keep_installed,
):
    local_video = video_path_for_apk(apk_path, output_dir)
    local_trace = trace_path_for_apk(apk_path, trace_output_dir)
    package_name = None
    remote_path = None
    remote_trace = None
    recorder = None
    droidbot_process = None
    droidbot_stdout_file = None
    droidbot_stderr_file = None
    droidbot_stdout_path = None
    droidbot_stderr_path = None
    profile_pid = None
    profile_started = False
    result = None
    cleanup_ok = True
    cleanup_message = ""
    local_xml_dir = xml_dir_for_apk(apk_path, xml_output_dir)
    local_droidbot_output = droidbot_output_path(apk_path, droidbot_output_dir)

    need_video = not (local_video.exists() and local_video.stat().st_size > 0)
    need_trace = not (local_trace.exists() and local_trace.stat().st_size > 0)
    need_xml = not xml_complete_for_apk(apk_path, xml_output_dir)
    if not need_video and not need_trace and not need_xml:
        return ApkRecordResult(True, f"Video, trace, and semantic report already exist: {local_video.name}, {local_trace.name}, {local_xml_dir.name}")

    try:
        badging = extract_badging(apk_path, aapt_path)
        package_name = get_package_name_from_badging(badging)
        launchable_activity = get_launchable_activity_from_badging(badging)

        if not need_video and not need_trace and need_xml and droidbot_has_native_states(local_droidbot_output):
            report_path = build_droidbot_semantic_stream(
                droidbot_output_dir=local_droidbot_output,
                output_dir=local_xml_dir,
                target_package=package_name,
            )
            return ApkRecordResult(True, f"Saved semantic report={report_path}", package_name=package_name)

        remote_path = remote_video_path(package_name)
        remote_trace = remote_trace_path(package_name)

        adb_cmd(adb_path, serial, "shell", "rm", "-f", remote_path, timeout=15, capture=True, check=False)
        if need_trace:
            adb_cmd(adb_path, serial, "shell", "rm", "-f", remote_trace, timeout=15, capture=True, check=False)
        install_apk(apk_path, package_name, adb_path, serial)

        if need_video:
            recorder = start_screenrecord(remote_path, seconds, bit_rate, video_size, adb_path, serial)
            time.sleep(1)

        start_app(package_name, launchable_activity, adb_path, serial)

        if need_trace:
            profile_pid = wait_for_pid(package_name, adb_path, serial, timeout=45)
            start_art_profile(profile_pid, remote_trace, adb_path, serial)
            profile_started = True

        droidbot_process, droidbot_stdout_file, droidbot_stderr_file, droidbot_stdout_path, droidbot_stderr_path = (
            start_droidbot_process(
                apk_path=apk_path,
                serial=serial,
                seconds=seconds,
                adb_path=adb_path,
                droidbot_root=droidbot_root,
                output_dir=local_droidbot_output,
                policy=droidbot_policy,
                event_interval=droidbot_event_interval,
                event_count=droidbot_event_count,
                debug_mode=droidbot_debug,
            )
        )

        wait_for_droidbot(
            droidbot_process,
            droidbot_stdout_file,
            droidbot_stderr_file,
            droidbot_stdout_path,
            droidbot_stderr_path,
            seconds,
        )
        droidbot_process = None

        if recorder:
            recorder.wait(timeout=seconds + 30)

        if profile_started:
            stop_art_profile(profile_pid, adb_path, serial)
            profile_started = False
            time.sleep(4)

        semantic_report = build_droidbot_semantic_stream(
            droidbot_output_dir=local_droidbot_output,
            output_dir=local_xml_dir,
            target_package=package_name,
        )

        saved_outputs = []
        if need_video:
            time.sleep(2)
            pull_video(remote_path, local_video, adb_path, serial)
            saved_outputs.append(f"video={local_video}")
        else:
            saved_outputs.append(f"video already exists={local_video.name}")

        if need_trace:
            pull_trace(remote_trace, local_trace, adb_path, serial)
            saved_outputs.append(f"trace={local_trace}")
        else:
            saved_outputs.append(f"trace already exists={local_trace.name}")

        if need_xml:
            saved_outputs.append(f"semantic report={semantic_report}")
        else:
            saved_outputs.append(f"semantic report refreshed={semantic_report.name}")

        result = ApkRecordResult(True, "Saved " + ", ".join(saved_outputs), package_name=package_name)
    except subprocess.TimeoutExpired as exc:
        result = ApkRecordResult(False, f"Timeout: {exc}", package_name=package_name)
    except FileNotFoundError as exc:
        result = ApkRecordResult(False, f"DroidBot semantic parse failed: {exc}", package_name=package_name)
    except ApkRunError as exc:
        result = ApkRecordResult(False, str(exc), package_name=package_name)
    except Exception as exc:  # pragma: no cover - defensive batch mode boundary
        result = ApkRecordResult(False, f"Unexpected error: {exc}", package_name=package_name)
    finally:
        if recorder and recorder.poll() is None:
            recorder.terminate()
            try:
                recorder.wait(timeout=5)
            except subprocess.TimeoutExpired:
                recorder.kill()
        if droidbot_process and droidbot_process.poll() is None:
            droidbot_process.terminate()
            try:
                droidbot_process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                droidbot_process.kill()
        if droidbot_stdout_file and not droidbot_stdout_file.closed:
            droidbot_stdout_file.close()
        if droidbot_stderr_file and not droidbot_stderr_file.closed:
            droidbot_stderr_file.close()
        if profile_started and profile_pid:
            try:
                stop_art_profile(profile_pid, adb_path, serial)
            except Exception:
                pass
        if remote_trace:
            try:
                adb_cmd(adb_path, serial, "shell", "rm", "-f", remote_trace, timeout=15, capture=True, check=False)
            except Exception:
                pass
        if package_name and remote_path:
            try:
                cleanup_ok, cleanup_message = cleanup(package_name, remote_path, adb_path, serial, keep_installed)
            except Exception as exc:
                cleanup_ok = False
                cleanup_message = f"cleanup raised {type(exc).__name__}: {exc}"

    if result is None:
        result = ApkRecordResult(False, "Unknown recording failure", package_name=package_name)
    result.cleanup_ok = cleanup_ok
    result.cleanup_message = cleanup_message
    result.package_name = package_name
    return result


def collect_apks(apk, apk_dir):
    if apk:
        apk_path = apk.resolve()
        validate_file(apk_path, "APK")
        return [apk_path]
    validate_directory(apk_dir, "APK directory")
    return sorted(apk_dir.glob("*.apk"))


def split_pending_apks(apk_paths, output_dir, trace_output_dir, xml_output_dir):
    pending = []
    skipped = []
    for apk_path in apk_paths:
        video_path = video_path_for_apk(apk_path, output_dir)
        trace_path = trace_path_for_apk(apk_path, trace_output_dir)
        video_exists = video_path.exists() and video_path.stat().st_size > 0
        trace_exists = trace_path.exists() and trace_path.stat().st_size > 0
        xml_exists = xml_complete_for_apk(apk_path, xml_output_dir)
        if video_exists and trace_exists and xml_exists:
            skipped.append(apk_path)
        else:
            pending.append(apk_path)
    return pending, skipped


def build_parser():
    parser = argparse.ArgumentParser(
        description="Install APKs on an Android Studio emulator, run them dynamically, and record MP4 videos."
    )
    parser.add_argument("--apk", type=Path, help="Record one APK file.")
    parser.add_argument("--apk-dir", type=Path, default=APK_DIR, help="Directory containing APK files.")
    parser.add_argument("--output-dir", type=Path, default=VIDEO_OUTPUT_DIR, help="Directory for MP4 videos.")
    parser.add_argument("--trace-output-dir", type=Path, default=TRACE_OUTPUT_DIR, help="Directory for ART trace files.")
    parser.add_argument("--xml-output-dir", type=Path, default=XML_OUTPUT_DIR, help="Directory for parsed DroidBot semantic reports.")
    parser.add_argument("--adb", type=Path, default=ADB_PATH, help="Path to adb.exe.")
    parser.add_argument("--aapt", type=Path, default=AAPT_PATH, help="Path to aapt.exe.")
    parser.add_argument("--emulator", type=Path, default=EMULATOR_PATH, help="Path to emulator.exe.")
    parser.add_argument("--serial", help="ADB serial, for example emulator-5554.")
    parser.add_argument("--avd-name", default=AVD_NAME, help="AVD name, used by --recovery-mode wipe-data.")
    parser.add_argument("--seconds", type=int, default=RECORD_SECONDS, help="Recording time, max 180 is safest.")
    parser.add_argument("--bit-rate", type=int, default=BIT_RATE, help="screenrecord bit rate.")
    parser.add_argument("--size", default=VIDEO_SIZE, help='Video size, for example "720x1280".')
    parser.add_argument("--droidbot-root", type=Path, default=DROIDBOT_ROOT, help="Path to local droidbot-master directory.")
    parser.add_argument("--droidbot-output-dir", type=Path, default=DROIDBOT_OUTPUT_DIR, help="Directory for DroidBot UTG/log outputs.")
    parser.add_argument("--droidbot-policy", default=DROIDBOT_POLICY, help="DroidBot input policy, for example dfs_greedy.")
    parser.add_argument(
        "--droidbot-event-interval",
        type=int,
        default=DROIDBOT_EVENT_INTERVAL_SECONDS,
        help="DroidBot interval in seconds between events.",
    )
    parser.add_argument("--droidbot-event-count", type=int, default=DROIDBOT_EVENT_COUNT, help="DroidBot max event count.")
    parser.add_argument("--droidbot-debug", action="store_true", help="Run DroidBot in debug mode.")
    parser.add_argument("--restart-every", type=int, default=RESTART_EMULATOR_EVERY, help="Reboot emulator after N APKs; 0 disables.")
    parser.add_argument("--keep-installed", action="store_true", help="Do not uninstall APK after recording.")
    parser.add_argument("--snapshot-name", default=SNAPSHOT_NAME, help="Clean snapshot name to save and restore.")
    parser.add_argument(
        "--recovery-mode",
        choices=("snapshot", "wipe-data"),
        default="snapshot",
        help="How to recover when APK cleanup fails.",
    )
    parser.add_argument("--no-snapshot", action="store_true", help="Disable automatic clean snapshot save/restore.")
    return parser


def main():
    args = build_parser().parse_args()
    validate_file(args.adb, "adb")
    validate_file(args.aapt, "aapt")
    validate_droidbot(args.droidbot_root, args.adb)
    if args.recovery_mode == "wipe-data":
        validate_file(args.emulator, "emulator")
        if not args.avd_name:
            raise ApkRunError("--avd-name is required when --recovery-mode wipe-data is used.")
    if args.keep_installed and not args.no_snapshot:
        raise ApkRunError("--keep-installed conflicts with automatic clean-state recovery. Use --no-snapshot for debugging.")

    if args.seconds < 1:
        raise ApkRunError("--seconds must be greater than 0.")
    if args.droidbot_event_interval < 0:
        raise ApkRunError("--droidbot-event-interval must be greater than or equal to 0.")
    if args.droidbot_event_count < 1:
        raise ApkRunError("--droidbot-event-count must be greater than 0.")
    if args.droidbot_policy in {"monkey", "none"}:
        raise ApkRunError(
            "--droidbot-policy must be a UI exploration policy such as dfs_greedy; "
            "actions-only mode does not use DroidBot monkey/none policies."
        )
    if args.seconds > 180:
        log("[!] Android screenrecord commonly caps --time-limit at 180 seconds.")

    all_apk_paths = collect_apks(args.apk, args.apk_dir)
    if not all_apk_paths:
        raise ApkRunError(f"No APK files found in {args.apk_dir}")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    args.trace_output_dir.mkdir(parents=True, exist_ok=True)
    args.droidbot_output_dir.mkdir(parents=True, exist_ok=True)
    args.xml_output_dir.mkdir(parents=True, exist_ok=True)
    apk_paths, skipped_apks = split_pending_apks(
        all_apk_paths,
        args.output_dir,
        args.trace_output_dir,
        args.xml_output_dir,
    )
    if skipped_apks:
        log(f"[*] Resume mode: skipping {len(skipped_apks)} APKs with existing MP4, trace, and semantic report.")
    if not apk_paths:
        log(f"[*] All {len(all_apk_paths)} APKs already have videos, traces, and semantic reports. Nothing to do.")
        return

    serial = choose_device(args.adb, args.serial)
    wait_for_boot(args.adb, serial)

    snapshot_enabled = not args.no_snapshot and args.recovery_mode == "snapshot"
    if snapshot_enabled and not is_emulator_serial(serial):
        raise ApkRunError("--recovery-mode snapshot requires an Android emulator serial, for example emulator-5554.")
    if snapshot_enabled:
        save_clean_snapshot(args.adb, serial, args.snapshot_name)

    log(f"[*] Using device: {serial}")
    log(f"[*] APK count: {len(apk_paths)} pending, {len(skipped_apks)} skipped, {len(all_apk_paths)} total")
    log(f"[*] Video output: {args.output_dir}")
    log(f"[*] Trace output: {args.trace_output_dir}")
    log(f"[*] Semantic report output: {args.xml_output_dir}")
    log(f"[*] DroidBot output: {args.droidbot_output_dir}")
    if args.no_snapshot:
        log("[!] Automatic clean-state recovery is disabled.")
    else:
        log(f"[*] Recovery mode: {args.recovery_mode}")

    iterator = tqdm(apk_paths, desc="Recording APKs") if tqdm is not None else apk_paths
    success_count = 0
    recovery_count = 0

    for index, apk_path in enumerate(iterator, start=1):
        result = record_apk(
            apk_path=apk_path,
            output_dir=args.output_dir,
            trace_output_dir=args.trace_output_dir,
            xml_output_dir=args.xml_output_dir,
            adb_path=args.adb,
            aapt_path=args.aapt,
            serial=serial,
            seconds=args.seconds,
            bit_rate=args.bit_rate,
            video_size=args.size,
            droidbot_root=args.droidbot_root,
            droidbot_output_dir=args.droidbot_output_dir,
            droidbot_policy=args.droidbot_policy,
            droidbot_event_interval=args.droidbot_event_interval,
            droidbot_event_count=args.droidbot_event_count,
            droidbot_debug=args.droidbot_debug,
            keep_installed=args.keep_installed,
        )
        if result.success:
            success_count += 1
            log(f"[+] {apk_path.name}: {result.message}")
        else:
            log(f"[-] {apk_path.name}: {result.message}")

        if not result.cleanup_ok:
            recovery_count += 1
            log(f"[!] {apk_path.name}: cleanup failed; restoring clean emulator state before continuing.")
            if result.cleanup_message:
                log(f"    cleanup detail: {result.cleanup_message}")
            if args.no_snapshot:
                log("[!] Recovery skipped because --no-snapshot is enabled. This emulator may be contaminated.")
            else:
                recover_clean_state(args, serial)

        if args.restart_every > 0 and index % args.restart_every == 0 and index < len(apk_paths):
            try:
                restart_emulator(args.adb, serial, args.emulator, args.avd_name)
            except ApkRunError as exc:
                raise ApkRunError(f"Periodic emulator restart failed after {index} APKs: {exc}") from exc

    log(f"[*] Done. {success_count}/{len(apk_paths)} pending APKs recorded successfully.")
    log(f"[*] Skipped existing video+trace pairs: {len(skipped_apks)}")
    log(f"[*] Emulator recoveries after cleanup failure: {recovery_count}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] Interrupted by user.")
    except ApkRunError as exc:
        print(f"[-] {exc}")
