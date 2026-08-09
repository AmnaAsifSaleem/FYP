"""
Proper Train/Test Split for CAVE-OT
Splits datasets into 80% train / 20% test BEFORE training
"""

import pandas as pd
from sklearn.model_selection import train_test_split

DATASET_FOLDER = r"D:\Downloads\CAVE-OT Datasets"

def split_dataset(input_file, train_file, test_file, test_size=0.2, random_state=42):
    """Split dataset into train and test sets"""
    print(f"\nProcessing {input_file}...")
    df = pd.read_csv(f'{DATASET_FOLDER}/{input_file}')
    print(f"  Total rows: {len(df)}")
    
    # Use simple random split for both datasets
    # (Many vendors have only 1 CVE, making stratification impossible)
    train_df, test_df = train_test_split(
        df, 
        test_size=test_size, 
        random_state=random_state
    )
    
    print(f"  Train set: {len(train_df)} rows ({len(train_df)/len(df)*100:.1f}%)")
    print(f"  Test set:  {len(test_df)} rows ({len(test_df)/len(df)*100:.1f}%)")
    
    # Save splits
    train_df.to_csv(f'{DATASET_FOLDER}/{train_file}', index=False)
    test_df.to_csv(f'{DATASET_FOLDER}/{test_file}', index=False)
    
    print(f"  ✓ Saved {train_file}")
    print(f"  ✓ Saved {test_file}")
    
    return train_df, test_df

def main():
    print("=" * 60)
    print("CAVE-OT TRAIN/TEST SPLIT")
    print("=" * 60)
    print("\nCreating proper train/test splits (80/20)...")
    
    # Split general dataset
    train_general, test_general = split_dataset(
        'training_ready.csv',
        'training_ready_train.csv',
        'training_ready_test.csv'
    )
    
    # Split OT dataset
    train_ot, test_ot = split_dataset(
        'ot_training_ready.csv',
        'ot_training_ready_train.csv',
        'ot_training_ready_test.csv'
    )
    
    print("\n" + "=" * 60)
    print("✓ SPLIT COMPLETE")
    print("=" * 60)
    print("\nTop 10 vendors in OT test set:")
    vendor_counts = test_ot['vendor'].value_counts().head(10)
    for vendor, count in vendor_counts.items():
        print(f"  {vendor}: {count}")
    
    print("\n⚠️  IMPORTANT: Retrain models using *_train.csv files only!")
    print("   Run: python model_trainer_proper.py")

if __name__ == "__main__":
    main()
