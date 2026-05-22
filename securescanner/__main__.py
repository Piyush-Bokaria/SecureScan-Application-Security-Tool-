"""Allow running SecureScan as: python -m securescanner"""

import sys
from securescanner.cli import main

sys.exit(main())
