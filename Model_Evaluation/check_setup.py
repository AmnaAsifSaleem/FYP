"""
CAVE-OT Setup Checker
Verifies that all required files and dependencies are in place
"""

import os
import sys

def check_python_version():
    """Check Python version"""
    version = sys.version_info
    if version.major >= 3 and version.minor >= 8:
        print(f"✓ Python {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print(f"✗ Python {version.major}.{version.minor}.{version.micro} (need 3.8+)")
        return False

def check_dependencies():
    """Check if required packages are installed"""
    required = ['pandas', 'numpy', 'sklearn', 'joblib', 'tqdm']
    missing = []
    
    for package in required:
        try:
            __import__(package)
            print(f"✓ {package}")
        except ImportError:
            print(f"✗ {package} (missing)")
            missing.append(package)
    
    return len(missing) == 0

def check_datasets():
    """Check if training datasets exist"""
    dataset_folder = os.path.dirname(os.path.abspath(__file__))
    files = [
        ('training_ready.csv', 206553),
        ('ot_training_ready.csv', 5991)
    ]
    
    all_exist = True
    for filename, expected_rows in files:
        filepath = os.path.join(dataset_folder, filename)
        if os.path.exists(filepath):
            size_mb = os.path.getsize(filepath) / (1024 * 1024)
            print(f"✓ {filename} ({size_mb:.1f} MB)")
        else:
            print(f"✗ {filename} (not found)")
            all_exist = False
    
    return all_exist

def check_models():
    """Check if models are trained"""
    model_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model")
    files = [
        'general_vectorizer.pkl',
        'general_matrix.pkl',
        'cve_database.pkl',
        'ot_vectorizer.pkl',
        'ot_matrix.pkl',
        'ot_cve_database.pkl'
    ]
    
    if not os.path.exists(model_folder):
        print(f"✗ Model folder not found: {model_folder}")
        return False
    
    all_exist = True
    for filename in files:
        filepath = os.path.join(model_folder, filename)
        if os.path.exists(filepath):
            size_mb = os.path.getsize(filepath) / (1024 * 1024)
            print(f"✓ {filename} ({size_mb:.1f} MB)")
        else:
            print(f"✗ {filename} (not found)")
            all_exist = False
    
    return all_exist

def check_scripts():
    """Check if all required scripts exist"""
    scripts = [
        'model_trainer.py',
        'cve_mapper.py',
        'risk_scorer.py',
        'requirements.txt'
    ]
    
    all_exist = True
    for script in scripts:
        if os.path.exists(script):
            print(f"✓ {script}")
        else:
            print(f"✗ {script} (not found)")
            all_exist = False
    
    return all_exist

def main():
    print("=" * 60)
    print("CAVE-OT SETUP CHECKER")
    print("=" * 60)
    
    checks = []
    
    print("\n[1/5] Checking Python version...")
    checks.append(check_python_version())
    
    print("\n[2/5] Checking Python dependencies...")
    checks.append(check_dependencies())
    
    print("\n[3/5] Checking training datasets...")
    checks.append(check_datasets())
    
    print("\n[4/5] Checking trained models...")
    models_exist = check_models()
    checks.append(models_exist)
    
    print("\n[5/5] Checking pipeline scripts...")
    checks.append(check_scripts())
    
    print("\n" + "=" * 60)
    if all(checks):
        print("✓ ALL CHECKS PASSED")
        print("=" * 60)
        print("\nYour CAVE-OT setup is complete!")
        print("\nNext steps:")
        if not models_exist:
            print("  1. Run: python model_trainer.py")
            print("  2. Run: python test_pipeline.py")
        else:
            print("  1. Run: python test_pipeline.py")
            print("  2. Create model_input.json with your devices")
            print("  3. Run: python cve_mapper.py")
            print("  4. Run: python risk_scorer.py")
    else:
        print("✗ SOME CHECKS FAILED")
        print("=" * 60)
        print("\nPlease fix the issues above before proceeding.")
        print("\nCommon fixes:")
        print("  - Install dependencies: pip install -r requirements.txt")
        print("  - Verify datasets are in: D:\\Downloads\\CAVE-OT Datasets\\")
        print("  - Train models: python model_trainer.py")
    
    print()

if __name__ == "__main__":
    main()
