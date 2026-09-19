from pathlib import Path
import subprocess
import sys


BASE_DIR = Path(__file__).resolve().parent

URL_TRAINER = BASE_DIR / "train_url_model.py"
TEXT_TRAINER = BASE_DIR / "train_text_model.py"


def run_trainer(script_path, model_name):
    print("\n" + "=" * 50)
    print(f"Training {model_name}...")
    print("=" * 50)

    result = subprocess.run(
        [sys.executable, str(script_path)],
        cwd=str(BASE_DIR.parent)
    )

    if result.returncode == 0:
        print(f"\n{model_name} training completed successfully. ✅")
    else:
        print(f"\n{model_name} training failed. ❌")

    return result.returncode


def main():
    print("PhishGuard ML Training")
    print("======================")

    if not URL_TRAINER.exists():
        print("ERROR: train_url_model.py not found.")
        return

    if not TEXT_TRAINER.exists():
        print("ERROR: train_text_model.py not found.")
        return

    url_result = run_trainer(
        URL_TRAINER,
        "URL Model"
    )

    text_result = run_trainer(
        TEXT_TRAINER,
        "Text Model"
    )

    print("\n" + "=" * 50)
    print("Training Summary")
    print("=" * 50)

    if url_result == 0:
        print("URL Model   : ✅ Ready")
    else:
        print("URL Model   : ❌ Failed")

    if text_result == 0:
        print("Text Model  : ✅ Ready")
    else:
        print("Text Model  : ❌ Failed")


if __name__ == "__main__":
    main()