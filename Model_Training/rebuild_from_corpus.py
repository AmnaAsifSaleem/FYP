"""Rebuild retrieval indexes from preserved CVE corpora, without inventing labels.
The corpus in existing artifacts is recoverable even when source CSVs are absent.
This does not reconstruct missing affected-version evidence or evaluation data.
"""
import os,sys,json,hashlib,tempfile,shutil
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from pipeline_paths import MODEL_FOLDER,DATASET_FOLDER
from snapshot_io import atomic_json

def corpus(df):
    return [' '.join([str(v)]*3+[str(p)]*2+[str(d)]) for v,p,d in zip(df['vendor'].fillna(''),df['product'].fillna(''),df['description'].fillna(''))]

def rebuild():
    root=Path(MODEL_FOLDER);datasets=Path(DATASET_FOLDER);datasets.mkdir(exist_ok=True)
    general=joblib.load(root/'cve_database.pkl');ot=joblib.load(root/'ot_cve_database.pkl')
    general.to_csv(datasets/'training_ready.csv',index=False);ot.to_csv(datasets/'ot_training_ready.csv',index=False)
    atomic_json(datasets/'RECOVERY_PROVENANCE.json',{'source':'Existing cve_database.pkl and ot_cve_database.pkl','general_rows':len(general),'ot_rows':len(ot),'missing_evidence':'Original policy labels and full CPE configurations are not recoverable from these artifacts.'})
    backup=root/'.backup'/'before-evidence-v2';backup.mkdir(parents=True,exist_ok=True)
    temp=Path(tempfile.mkdtemp(prefix='rebuild-',dir=root))
    try:
        vector=TfidfVectorizer(ngram_range=(1,2),min_df=2,max_df=.95,max_features=50000,sublinear_tf=True)
        matrix=vector.fit_transform(corpus(general));joblib.dump(vector,temp/'general_vectorizer.pkl');joblib.dump(matrix,temp/'general_matrix.pkl');joblib.dump(general,temp/'cve_database.pkl')
        ot_vector=TfidfVectorizer(ngram_range=(1,2),min_df=1,max_df=.95,max_features=50000,sublinear_tf=True,vocabulary=vector.vocabulary_)
        ot_matrix=ot_vector.fit_transform(corpus(ot));joblib.dump(ot_vector,temp/'ot_vectorizer.pkl');joblib.dump(ot_matrix,temp/'ot_matrix.pkl');joblib.dump(ot,temp/'ot_cve_database.pkl')
        hashes={}
        for file in temp.glob('*.pkl'):
            destination=root/file.name
            if destination.exists() and not (backup/file.name).exists():shutil.copy2(destination,backup/file.name)
            hashes[file.name]=hashlib.sha256(file.read_bytes()).hexdigest()
        # No running monitor should read while an explicit rebuild is in progress.
        for file in temp.glob('*.pkl'):os.replace(file,root/file.name)
        atomic_json(root/'training_manifest.json',{'method':'TF-IDF token weighting corrected; OT-specific fitting with shared vocabulary','general_rows':len(general),'ot_rows':len(ot),'hashes':hashes,'applicability':'Candidate retrieval only; legacy version bounds cannot confirm applicability','evaluation':'No new accuracy claim; independent applicability benchmark required'})
    finally:
        temp.resolve().relative_to(root.resolve())
        if not temp.name.startswith('rebuild-'):raise ValueError('Unexpected temporary directory')
        shutil.rmtree(temp)
    print(f'Rebuilt indexes from {len(general)} general and {len(ot)} OT corpus rows; original artifacts preserved.')

if __name__=='__main__':rebuild()
