#!/usr/bin/env python3
import os, glob, time
from datetime import datetime
from pathlib import Path
import pandas as pd
import numpy as np
import joblib

from rich.console import Console
from rich.progress import track
from rich.panel import Panel

import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import OneHotEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score, precision_recall_fscore_support

# ------------------- Config -------------------
TRAIN_DIR = "run treino"
TEST_DIR = "run teste"
RESULTS_DIR = "resultados"

console = Console()

# ------------------- Util -------------------
def ensure_dirs():
    Path(RESULTS_DIR).mkdir(parents=True, exist_ok=True)

def list_csv_files_with_counts(directory):
    files = sorted(glob.glob(os.path.join(directory, "*.csv")))
    items = []
    for f in files:
        try:
            n = sum(1 for _ in open(f, "r", encoding="utf-8", errors="ignore")) - 1
            n = max(n,0)
        except Exception:
            n = -1
        items.append((os.path.basename(f), f, n))
    return items

def load_and_concat_csvs(files):
    dfs = []
    for _, path, _ in files:
        console.log(f"→ A ler {path} ...")
        df = pd.read_csv(path)
        #df["_source_file"] = os.path.basename(path)
        dfs.append(df)
    return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()

def plot_confusion_matrix(cm, labels, out_path):
    plt.figure(figsize=(6,5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=labels, yticklabels=labels)
    plt.ylabel("True")
    plt.xlabel("Predicted")
    plt.title("Confusion Matrix")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()

def save_html_report(metrics_text, cm_path, fi_path, file_list_train, file_list_test,
                     html_path, results_csv_path, metrics_csv_path):
    ts = datetime.utcnow().isoformat() + "Z"
    html = f"""<!DOCTYPE html>
<html lang="pt">
<head>
<meta charset="utf-8">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
body {{ background-color:#121212; color:#e0e0e0; font-family:'Segoe UI',sans-serif; margin:0; padding:0; }}
h1,h2 {{ color:#00bcd4; }}
.metric-card {{ background:#1e1e1e; border-radius:12px; padding:20px; text-align:center; box-shadow:0 0 10px rgba(0,0,0,0.5); }}
.metric-value {{ font-size:1.6rem; font-weight:bold; color:#00e676; }}
.metric-label {{ font-size:0.9rem; color:#aaa; }}
.section {{ margin-top:40px; }}
img {{ max-width:100%; border-radius:8px; }}
pre {{ background-color:#1c1c1c; border-radius:6px; padding:10px; color:#e0e0e0; overflow-x:auto; }}
footer {{ text-align:center; color:#777; margin-top:50px; font-size:0.9em; }}
</style>
</head>
<body>
<div class="container my-5">
<h1 class="text-center mb-4">📊 Relatório de Treino - Mod-Sentinel</h1>
<p class="text-center text-secondary">Gerado a <strong>{ts}</strong></p>
<div class="row text-center g-3 mb-5">
  <div class="col-md-3"><div class="metric-card"><div class="metric-value">✔️</div><div class="metric-label">Modelo treinado</div></div></div>
  <div class="col-md-3"><div class="metric-card"><div class="metric-value">{len(file_list_train)}</div><div class="metric-label">Ficheiros de treino</div></div></div>
  <div class="col-md-3"><div class="metric-card"><div class="metric-value">{len(file_list_test)}</div><div class="metric-label">Ficheiros de teste</div></div></div>
</div>

<div class="section"><h2>📈 Métricas</h2><pre>{metrics_text}</pre></div>
<div class="section"><h2>📊 Matriz de Confusão</h2>{f'<img src="{os.path.basename(cm_path)}">' if os.path.exists(cm_path) else '<p>Sem matriz disponível.</p>'}</div>
<div class="section"><h2>🏗️ Importância das Features</h2>{f'<img src="{os.path.basename(fi_path)}">' if os.path.exists(fi_path) else '<p>Sem gráfico disponível.</p>'}</div>

<div class="section">
<h2>🧾 Ficheiros de treino</h2><ul>{''.join(f'<li>{name} — {n} linhas</li>' for name, path, n in file_list_train)}</ul>
<h2>📁 Ficheiros de teste</h2><ul>{''.join(f'<li>{name} — {n} linhas</li>' for name, path, n in file_list_test)}</ul>
</div>

<div class="section text-center">
<h2>📤 Exportações</h2>
<p><a href="{os.path.basename(results_csv_path)}" class="btn btn-outline-info btn-sm">🔹 Resultados CSV</a></p>
<p><a href="{os.path.basename(metrics_csv_path)}" class="btn btn-outline-success btn-sm">🔹 Classification Report CSV</a></p>
</div>

<footer><hr><p>Relatório gerado automaticamente pelo sistema de treino Mod-Sentinel.</p></footer>
</div></body></html>"""

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

# ------------------- Pipeline -------------------
def build_pipeline(X):
    num_cols = [c for c in X.columns if pd.api.types.is_numeric_dtype(X[c])]
    cat_cols = [c for c in X.columns if not pd.api.types.is_numeric_dtype(X[c])]

    num_transformer = SimpleImputer(strategy='median')
    cat_transformer = Pipeline([
        ('imp', SimpleImputer(strategy='constant', fill_value='missing')),
        ('ohe', OneHotEncoder(handle_unknown='ignore', sparse_output=False))
    ])

    preprocessor = ColumnTransformer([
        ('num', num_transformer, num_cols),
        ('cat', cat_transformer, cat_cols)
    ], remainder='drop')

    clf = RandomForestClassifier(
        n_estimators=300, random_state=42, class_weight='balanced', n_jobs=-1
    )

    pipe = Pipeline([('pre', preprocessor), ('clf', clf)])
    return pipe

# ------------------- Core -------------------
def train_and_evaluate():
    ensure_dirs()
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    # Listar ficheiros
    train_files = list_csv_files_with_counts(TRAIN_DIR)
    test_files = list_csv_files_with_counts(TEST_DIR)

    df_train = load_and_concat_csvs(train_files)
    df_test = load_and_concat_csvs(test_files)

    drop_cols = ['timestamp','src_mac','dst_mac','src_ip','dst_ip','payload','transaction_id'] #  manter payload para análise
    target_col = 'malicious'

    if target_col not in df_train.columns:
        console.print("[red]ERRO: coluna 'malicious' necessária[/red]")
        return

    # Separar features/target
    X_train = df_train.drop(columns=[target_col]+drop_cols, errors='ignore')
    y_train = df_train[target_col]

    X_test = df_test.drop(columns=[target_col]+drop_cols, errors='ignore') if not df_test.empty else pd.DataFrame()
    y_test = df_test[target_col] if target_col in df_test.columns else None

    # Construir pipeline
    pipe = build_pipeline(X_train)
    console.print("A treinar modelo...")
    for _ in track(range(10), description="Treino em progresso"):
        time.sleep(0.05)
    pipe.fit(X_train, y_train)

    # Guardar modelo
    model_file = os.path.join(RESULTS_DIR, f"modelo_{ts}.pkl")
    joblib.dump(pipe, model_file)
    console.print(f"[green]Modelo guardado em:[/green] {model_file}")

    # Predição
    if not X_test.empty:
        console.print("Predicting new results...")
        y_pred = pipe.predict(X_test)
        df_test['predicted'] = y_pred
        if y_test is not None:
            df_test['true'] = y_test.values

        # Guardar resultados
        results_csv = os.path.join(RESULTS_DIR, f"resultados_{ts}.csv")
        df_test.to_csv(results_csv, index=False)
        console.print(f"[green]Resultados guardados em:[/green] {results_csv}")

        if y_test is not None:
            # Métricas
            acc = accuracy_score(y_test, y_pred)
            prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted', zero_division=0)
            cm = confusion_matrix(y_test, y_pred)
            report_dict = classification_report(y_test, y_pred, output_dict=True)
            report_text = classification_report(y_test, y_pred)

            metrics_csv = os.path.join(RESULTS_DIR, f"classification_report_{ts}.csv")
            pd.DataFrame(report_dict).transpose().to_csv(metrics_csv)
            console.print(f"[green]Métricas guardadas em:[/green] {metrics_csv}")

            # Matriz de confusão
            cm_png = os.path.join(RESULTS_DIR, f"matriz_confusao_{ts}.png")
            plot_confusion_matrix(cm, sorted(y_test.unique()), cm_png)
            console.print(f"[green]Matriz confusão guardada em:[/green] {cm_png}")

            # Feature importance
            fi = pipe.named_steps['clf'].feature_importances_
            features = pipe.named_steps['pre'].get_feature_names_out()
            fi_df = pd.DataFrame({"Feature": features, "Importance": fi}).sort_values("Importance", ascending=False)
            fi_png = os.path.join(RESULTS_DIR, f"feature_importance_{ts}.png")
            plt.figure(figsize=(10,6))
            sns.barplot(x="Importance", y="Feature", data=fi_df.head(15))
            plt.tight_layout()
            plt.savefig(fi_png)
            plt.close()
            console.print(f"[green]Feature importance guardada em:[/green] {fi_png}")

            # HTML report
            html_report = os.path.join(RESULTS_DIR, f"relatorio_{ts}.html")
            save_html_report(
                metrics_text=report_text,
                cm_path=cm_png,
                fi_path=fi_png,
                file_list_train=train_files,
                file_list_test=test_files,
                html_path=html_report,
                results_csv_path=results_csv,
                metrics_csv_path=metrics_csv
            )
            console.print(f"[green]HTML report gerado a:[/green] {html_report}")

    console.print("[green]Treino e avaliação concluídos.[/green]")

# ------------------- Executar -------------------
# ------------------- CLI / Execução -------------------
def main():
    console.clear()
    console.print(Panel.fit(
        "[bold cyan]🚀 Mod-Sentinel[/bold cyan]\n"
        "[bold white]Treino e Avaliação de Modelos de Machine Learning[/bold white]\n"
        "[dim]Powered by Python, Scikit-learn & Rich[/dim]",
        title="✨ Mod-Sentinel v1.0 ✨",
        border_style="bright_magenta"
    ))

    console.print("\n[bold yellow]A iniciar treino e avaliação automática...[/bold yellow]\n")
    train_and_evaluate()
    console.print("\n[bold green]Execução completa![/bold green] ✅")

if __name__ == "__main__":
    main()
