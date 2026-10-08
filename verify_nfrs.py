"""Verification entry point: executed regression tests, not keyword assertions."""
import os,sys,subprocess
root=os.path.dirname(os.path.abspath(__file__))
if __name__=='__main__':
    result=subprocess.run([sys.executable,'-m','pytest',os.path.join(root,'tests'),'-q','-p','no:cacheprovider'])
    print('Live Docker/IDS availability and production load require separate environment tests.')
    sys.exit(result.returncode)
