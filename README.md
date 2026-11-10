# 455-MS-project

# To use `uv` project manager:

This project uses **uv** for fast, painless Python package and version management. You do not need to manually create or activate a virtual environment.

## Getting Started

### 1. Install uv
If you don't have uv installed yet, open your terminal and run the command for your operating system:

* **Mac / Linux:**
  ```bash
    curl -LsSf https://astral.sh/uv/install.sh | sh
  ```
* **Windows (PowerShell):**
  ```powershell
  powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
  ```

### 2. Run the Project
To install the dependencies and run the script using Python 3.14 all in a single step, simply run:

```bash
uv run main.py
```

## Adding New Packages

If you need to install a new Python package, **do not use pip**.

Always run `git pull` before adding any new packages to ensure your local configuration files match the team's latest version.

Instead, use `uv add` in your terminal:
```bash
uv add <package_name>
```

### Why this matters:
* This automatically installs the package into your local environment.
* It instantly updates our shared `pyproject.toml` and `uv.lock` files.
* When you commit and push those file changes to GitHub, the rest of the team will automatically get the new packages the next time they type `uv run main.py`.


*(Note: uv will automatically download Python 3.14 in the background if you don't have it, create the virtual environment, install the packages, and run your code).*
