import os
import sys
import runpy

# Set the root directory in sys.path so 'scanner' is fully visible
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)
os.chdir(project_root)

# Execute main/app.py directly as __main__ without modifying a single line of your file
if __name__ == "__main__":
    runpy.run_path("main/app.py", run_name="__main__")
