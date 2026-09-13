"""Install the built wheel into an isolated target and run its bundled demo outside the repo."""

import subprocess
import sys
import tempfile
from pathlib import Path

wheel = next((Path(__file__).resolve().parents[1] / "dist").glob("*.whl"))
with tempfile.TemporaryDirectory(prefix="aegis-wheel-") as temporary:
    root = Path(temporary)
    target = root / "installed"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--target",
            str(target),
            str(wheel),
        ],
        check=True,
    )
    code = (
        "import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); "
        "import aegis_cloud; "
        "assert Path(aegis_cloud.__file__).is_relative_to(Path(sys.argv[1])); "
        "from aegis_cloud.cli import main; "
        "assert main(['demo','--out','demo']) == 0; "
        "assert main(['verify','demo']) == 0"
    )
    subprocess.run([sys.executable, "-I", "-c", code, str(target)], cwd=root, check=True)
