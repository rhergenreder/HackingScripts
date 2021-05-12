import os
import sys

__doc__ = __doc__ or ""
__all__ = ["util","fileserver","xss_handler","genRevShell"]

inc_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(inc_dir)
