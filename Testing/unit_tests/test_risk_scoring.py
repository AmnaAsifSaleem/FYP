"""Compatibility runner for production contextual-risk regression tests."""
import os,sys,subprocess
root=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if __name__=='__main__':
    result=subprocess.run([sys.executable,'-m','pytest',os.path.join(root,'tests','test_evidence_flow.py'),'-q','-p','no:cacheprovider'])
    sys.exit(result.returncode)
