# detect_anomalies.py
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
import argparse
import os

def main(csv_path, output_path, contamination):
    df = pd.read_csv(csv_path)

    # Colunas a descartar (identificadores / muito alta cardinalidade)
    drop_cols = ['timestamp','src_mac','dst_mac','src_ip','dst_ip','payload','transaction_id','malicious']
    features = df.drop(columns=[c for c in drop_cols if c in df.columns])

    # Separar numéricas e categóricas
    num_cols = [c for c in features.columns if features[c].dtype in [int, float, 'int64', 'float64']]
    cat_cols = [c for c in features.columns if c not in num_cols]

    # Preprocess
    preprocessor = ColumnTransformer(transformers=[
        ('num', SimpleImputer(strategy='median'), num_cols),
        ('cat', Pipeline([('imp', SimpleImputer(strategy='constant', fill_value='missing')),
                         ('ohe', OneHotEncoder(handle_unknown='ignore', sparse_output=False))]), cat_cols)
    ], remainder='drop')

    clf = IsolationForest(n_estimators=200, contamination=contamination, random_state=42)
    pipe = Pipeline([('pre', preprocessor), ('clf', clf)])

    X = features.copy()
    pipe.fit(X)

    scores = pipe.decision_function(X)  # quanto maior => mais normal
    preds = pipe.predict(X)             # 1 = normal, -1 = anomalia

    df_out = df.copy()
    df_out['anomaly_score'] = scores
    df_out['anomaly'] = preds

    # Ordenar por mais anómalo (menor score) e salvar
    df_out_sorted = df_out.sort_values('anomaly_score')
    df_out_sorted.to_csv(output_path, index=False)
    print(f"Resultado gravado em: {output_path}")
    print("Top 10 anomalias (csv salvo):")
    print(df_out_sorted[['timestamp','src_ip','dst_ip','src_port','dst_port','function_code','length','flags','anomaly_score','anomaly']].head(10).to_string(index=False))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detecta anomalias com IsolationForest")
    parser.add_argument("--csv", required=True, help="Caminho para o CSV de input")
    parser.add_argument("--out", default="anomalies_out.csv", help="CSV de output com scores e marcações")
    parser.add_argument("--contamination", type=float, default=0.01, help="Fração esperada de anomalias (ex.: 0.01 = 1%)")
    args = parser.parse_args()
    main(args.csv, args.out, args.contamination)
