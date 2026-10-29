import argparse
import logging
import os
import sys
import time
import traceback
from pathlib import Path


DROIDBOT_ROOT = Path(os.getenv("DROIDBOT_ROOT", str(Path(__file__).resolve().parents[2] / "external" / "droidbot")))
if DROIDBOT_ROOT.exists():
    sys.path.insert(0, str(DROIDBOT_ROOT))

from droidbot.app import App
from droidbot.device import Device
from droidbot.input_manager import InputManager


LIFECYCLE_EVENT_NAMES = {"IntentEvent", "KillAppEvent", "SpawnEvent"}
APP_INITIATED_EXTERNAL_EVENT_NAMES = {"TouchEvent", "LongTouchEvent", "SetTextEvent", "SelectEvent"}
NEVER_ALLOWED_EXTERNAL_PACKAGES = {
    "com.android.launcher3",
    "com.google.android.apps.nexuslauncher",
    "com.android.systemui",
}


def is_lifecycle_event(event):
    if event is None:
        return True
    return event.__class__.__name__ in LIFECYCLE_EVENT_NAMES


def is_app_initiated_external_event(event):
    return event is not None and event.__class__.__name__ in APP_INITIATED_EXTERNAL_EVENT_NAMES


def package_from_activity(activity):
    if not activity:
        return None
    if "/" in activity:
        return activity.split("/", 1)[0]
    return activity


def foreground_package(device):
    activity = device.get_top_activity_name()
    return activity, package_from_activity(activity)


def return_to_target_app(device, app, logger, reason, activity=None):
    logger.info("Returning to target app %s. reason=%s current=%s", app.get_package_name(), reason, activity)
    device.start_app(app)
    time.sleep(1)


def fallback_external_ui_event(input_manager):
    state = getattr(input_manager.policy, "current_state", None)
    if state is None:
        state = input_manager.device.get_current_state()
    if state is None:
        return None
    for candidate in state.get_possible_input():
        if not is_lifecycle_event(candidate):
            return candidate
    return None


def sleep_interval(interval, deadline):
    if interval <= 0:
        return
    if deadline is None:
        time.sleep(interval)
        return
    remaining = deadline - time.time()
    if remaining > 0:
        time.sleep(min(interval, remaining))


def run_actions(args):
    os.makedirs(args.output_dir, exist_ok=True)
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)
    logger = logging.getLogger("DroidBotActionsOnly")

    device = None
    input_manager = None
    generated_count = 0
    sent_count = 0
    skipped_count = 0
    forced_return_count = 0
    allowed_external_count = 0
    external_fallback_count = 0
    allowed_external_package = None
    deadline = time.time() + args.timeout if args.timeout and args.timeout > 0 else None

    try:
        device = Device(
            device_serial=args.serial,
            is_emulator=args.is_emulator,
            output_dir=args.output_dir,
            cv_mode=args.cv,
            grant_perm=False,
            enable_accessibility_hard=False,
        )
        app = App(args.apk, output_dir=args.output_dir)
        input_manager = InputManager(
            device=device,
            app=app,
            policy_name=args.policy,
            random_input=args.random,
            event_count=args.count,
            event_interval=args.interval,
            script_path=args.script,
            profiling_method=None,
            master=None,
            replay_output=None,
        )
        if input_manager.policy is None:
            raise RuntimeError("actions-only mode requires a DroidBot UI exploration policy")

        device.set_up()
        device.connect()
        target_package = app.get_package_name()

        while input_manager.enabled and generated_count < args.count:
            if deadline is not None and time.time() >= deadline:
                break
            try:
                pre_activity, pre_package = foreground_package(device)
                if pre_package == target_package:
                    allowed_external_package = None
                elif allowed_external_package and pre_package == allowed_external_package:
                    pass
                else:
                    forced_return_count += 1
                    return_to_target_app(device, app, logger, "unrelated_foreground_before_event", pre_activity)
                    allowed_external_package = None
                    sleep_interval(args.interval, deadline)
                    continue

                event = input_manager.policy.generate_event()
                generated_count += 1
                if is_lifecycle_event(event):
                    if allowed_external_package and pre_package == allowed_external_package:
                        event = fallback_external_ui_event(input_manager)
                        if event is not None:
                            external_fallback_count += 1
                            logger.info("Replacing lifecycle event with external UI event: %s", event.__class__.__name__)
                        else:
                            skipped_count += 1
                            logger.info("Skipping DroidBot lifecycle event in external app: None")
                            sleep_interval(args.interval, deadline)
                            continue
                    else:
                        skipped_count += 1
                        logger.info("Skipping DroidBot lifecycle event: %s", event.__class__.__name__ if event else "None")
                        sleep_interval(args.interval, deadline)
                        continue
                input_manager.add_event(event)
                sent_count += 1

                post_activity, post_package = foreground_package(device)
                if post_package == target_package:
                    allowed_external_package = None
                elif post_package in NEVER_ALLOWED_EXTERNAL_PACKAGES:
                    forced_return_count += 1
                    return_to_target_app(device, app, logger, "blocked_external_package", post_activity)
                    allowed_external_package = None
                elif pre_package == target_package and is_app_initiated_external_event(event) and post_package:
                    allowed_external_package = post_package
                    allowed_external_count += 1
                    logger.info("Allowing app-initiated external package: %s via %s", post_package, event.__class__.__name__)
                elif allowed_external_package and post_package == allowed_external_package:
                    pass
                elif post_package != target_package:
                    forced_return_count += 1
                    return_to_target_app(device, app, logger, "unrelated_foreground_after_event", post_activity)
                    allowed_external_package = None
            except KeyboardInterrupt:
                break
            except Exception as exc:
                logger.warning("exception during DroidBot action generation: %s", exc)
                traceback.print_exc()
                sleep_interval(args.interval, deadline)

        logger.info(
            "DroidBot actions-only finished: generated=%d, sent=%d, skipped_lifecycle=%d, allowed_external=%d, forced_returns=%d, external_fallback=%d",
            generated_count,
            sent_count,
            skipped_count,
            allowed_external_count,
            forced_return_count,
            external_fallback_count,
        )
    finally:
        if input_manager is not None:
            input_manager.stop()
        if device is not None:
            device.disconnect()


def build_parser():
    parser = argparse.ArgumentParser(description="Run DroidBot UI actions without app lifecycle management.")
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--apk")
    parser.add_argument("--serial")
    parser.add_argument("--output-dir")
    parser.add_argument("--policy", default="dfs_greedy")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--interval", type=int, default=1)
    parser.add_argument("--count", type=int, default=100000000)
    parser.add_argument("--script")
    parser.add_argument("--random", action="store_true")
    parser.add_argument("--cv", action="store_true")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--is-emulator", action="store_true")
    return parser


def main():
    args = build_parser().parse_args()
    if args.self_check:
        print("DroidBot actions-only runner ready")
        return
    missing = [name for name in ("apk", "serial", "output_dir") if not getattr(args, name)]
    if missing:
        raise RuntimeError("missing required arguments: " + ", ".join(missing))
    run_actions(args)


if __name__ == "__main__":
    main()
