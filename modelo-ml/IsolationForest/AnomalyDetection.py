#!/usr/bin/env python3
import os
import glob
import time
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
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score, precision_recall_fscore_support

# ------------------- Config -------------------
TRAIN_DIR = "run treino"
TEST_DIR = "run teste"
RESULTS_DIR = "resultados"
MODEL_PREFIX = "modelo_iso"
CONTAMINATION = 0.4
RANDOM_STATE = 42
MAX_UNIQUE_OHE = 100  # máximo de valores únicos para one-hot

console = Console()

# ------------------- Util -------------------
def ensure_dirs():
    Path(RESULTS_DIR).mkdir(parents=True, exist_ok=True)

def list_csv_files_with_counts(directory):
    files = sorted(glob.glob(os.path.join(directory, "*.csv")))
    items = []
    for f in files:
        try:
            with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                n = sum(1 for _ in fh) - 1
                n = max(n, 0)
        except Exception:
            n = -1
        items.append((os.path.basename(f), f, n))
    return items

def load_and_concat_csvs(files, add_source=False):
    dfs = []
    for _, path, _ in files:
        console.log(f"→ A ler {path} ...")
        try:
            df = pd.read_csv(path)
        except Exception as e:
            console.log(f"[red]Erro ao ler {path}: {e}[/red]")
            continue
        if add_source:
            df["_source_file"] = os.path.basename(path)
        dfs.append(df)
    return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()

def preprocess_datetime(df):
    for col in df.columns:
        if df[col].dtype == object:
            try:
                # tenta converter para datetime (com formato fixo)
                df[col] = pd.to_datetime(df[col], format="%Y-%m-%d %H:%M:%S.%f", errors='coerce')
            except Exception:
                continue  # não é datetime
        if np.issubdtype(df[col].dtype, np.datetime64):
            # converte datetime para timestamp em segundos (int64)
            df[col] = df[col].astype('int64') // 10**9
    return df


def plot_hist_anomaly_score(scores, out_path):
    plt.figure(figsize=(8,4))
    sns.histplot(scores, bins=80, kde=False)
    plt.title("Distribuição de anomaly_score")
    plt.xlabel("anomaly_score (IsolationForest)")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()

def plot_confusion_matrix(cm, labels, out_path):
    plt.figure(figsize=(6,5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=labels, yticklabels=labels)
    plt.ylabel("True")
    plt.xlabel("Predicted")
    plt.title("Confusion Matrix")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()

def save_html_report(metrics_text, file_list_train, file_list_test,
                     html_path, results_csv_path, metrics_csv_path=None,
                     hist_path=None, cm_path=None):
    os.makedirs(os.path.dirname(html_path), exist_ok=True)

    hist_block = f'<p><img src="{os.path.basename(hist_path)}" class="img-fluid rounded shadow" alt="Histograma"></p>' if hist_path else ''
    cm_block = f'<p><img src="{os.path.basename(cm_path)}" class="img-fluid rounded shadow" alt="Matriz de Confusão"></p>' if cm_path else ''

    def _get_filename_safe(f):
        if isinstance(f, (tuple, list)):
            f = f[0]
        return os.path.basename(str(f))

    train_list = ''.join([f"<li>{_get_filename_safe(f)}</li>" for f in file_list_train]) if file_list_train else "<li>Nenhum ficheiro usado</li>"
    test_list = ''.join([f"<li>{_get_filename_safe(f)}</li>" for f in file_list_test]) if file_list_test else "<li>Nenhum ficheiro usado</li>"

    csv_links = f"""
    <div class="mt-3">
        <a href="{os.path.basename(results_csv_path)}" class="btn btn-outline-primary btn-sm">📄 Resultados (CSV)</a>
        {f'<a href="{os.path.basename(metrics_csv_path)}" class="btn btn-outline-secondary btn-sm ms-2">📈 Métricas (CSV)</a>' if metrics_csv_path else ''}
    </div>
    """

    html = f"""
    <!DOCTYPE html>
    <html lang="pt">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Relatório de Treino - ModSentinel</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {{
                font-family: 'Segoe UI', sans-serif;
                margin: 40px;
                background-color: #f8f9fa;
            }}
            .section {{
                background: white;
                padding: 25px;
                border-radius: 12px;
                margin-bottom: 30px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            }}
            h1 {{
                color: #0d6efd;
                font-size: 1.9rem;
                margin-bottom: 20px;
            }}
            h2 {{
                color: #212529;
                font-size: 1.3rem;
                margin-top: 25px;
            }}
            pre {{
                background-color: #f0f0f0;
                padding: 10px;
                border-radius: 6px;
                font-size: 0.9rem;
                white-space: pre-wrap;
            }}
            .img-fluid {{
                max-width: 90%;
                display: block;
                margin: 10px auto;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>📘 Relatório de Treino - ModSentinel</h1>

            <div class="section">
                <h2>📁 Ficheiros Usados</h2>
                <strong>Treino:</strong>
                <ul>{train_list}</ul>
                <strong>Teste:</strong>
                <ul>{test_list}</ul>
                {csv_links}
            </div>

            <div class="section">
                <h2>🧠 Métricas do Modelo</h2>
                <pre>{metrics_text}</pre>
            </div>

            <div class="section">
                <h2>📊 Visualizações</h2>
                {hist_block}
                {cm_block}
            </div>

            <footer class="text-center mt-4 text-muted">
                <hr>
                <small>Mod-Sentinel: Relatório gerado automaticamente.</small>
            </footer>
        </div>
    </body>
    </html>
    """

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

# ------------------- Pipeline otimizado -------------------
def build_preprocessor(X):
    num_cols = [c for c in X.columns if pd.api.types.is_numeric_dtype(X[c])]
    cat_cols = [c for c in X.columns if not pd.api.types.is_numeric_dtype(X[c])]

    cat_cols_to_encode = [c for c in cat_cols if X[c].nunique() <= MAX_UNIQUE_OHE]
    cat_cols_passthrough = list(set(cat_cols) - set(cat_cols_to_encode))

    num_transformer = SimpleImputer(strategy='median')
    cat_transformer = Pipeline([
        ('imp', SimpleImputer(strategy='constant', fill_value='missing')),
        ('ohe', OneHotEncoder(handle_unknown='ignore', sparse_output=True))
    ])

    preprocessor = ColumnTransformer([
        ('num', num_transformer, num_cols),
        ('cat_enc', cat_transformer, cat_cols_to_encode)
        # colunas grandes ficam fora do treino, adicionadas depois para relatório
    ], remainder='drop')

    return preprocessor, num_cols, cat_cols

# ------------------- Core -------------------
def train_anomaly_detection():
    ensure_dirs()
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    # --- Listar ficheiros ---
    train_files = list_csv_files_with_counts(TRAIN_DIR)
    test_files = list_csv_files_with_counts(TEST_DIR)

    console.rule("[bold cyan]Ficheiros de treino encontrados")
    for name, path, n in train_files:
        console.print(f" • {name} — {n} linhas")
    console.rule("[bold cyan]Ficheiros de teste encontrados")
    for name, path, n in test_files:
        console.print(f" • {name} — {n} linhas")

    if not train_files:
        console.print("[red]❌ Não há ficheiros de treino em 'run treino/'. Coloca aí amostras benignas e tenta novamente.[/red]")
        return

    # --- Carregar datasets ---
    df_train = load_and_concat_csvs(train_files)
    df_test = load_and_concat_csvs(test_files, add_source=True) if test_files else pd.DataFrame()

    # --- Validar coluna 'malicious' ---
    if 'malicious' not in df_train.columns:
        raise ValueError("A coluna 'malicious' não foi encontrada nos dados de treino.")
    if not df_test.empty and 'malicious' not in df_test.columns:
        console.print("[yellow]⚠️ Ficheiros de teste sem coluna 'malicious' — apenas serão calculados scores, sem métricas.[/yellow]")

    # --- Remover colunas irrelevantes ---
    cols_to_remove = ['timestamp', 'payload', 'src_ip', 'dst_ip', 'src_mac', 'dst_mac']
    df_train = df_train.drop(columns=[c for c in cols_to_remove if c in df_train.columns], errors='ignore')
    df_test = df_test.drop(columns=[c for c in cols_to_remove if c in df_test.columns], errors='ignore')

    # --- Filtrar apenas amostras benignas para treino ---
    df_train_normal = df_train[df_train['malicious'] == 0].copy()
    if len(df_train_normal) < 10:
        console.print("[red]⚠️ Atenção: poucos dados benignos para treino — resultados podem ser instáveis.[/red]")

    X_train = df_train_normal.drop(columns=['malicious'])
    console.print(f"[cyan]Treino com {len(X_train)} amostras benignas e {X_train.shape[1]} atributos.[/cyan]")

    # --- Construir pipeline ---
    preprocessor, num_cols, cat_cols = build_preprocessor(X_train)
    iso = IsolationForest(
        n_estimators=200,
        contamination=CONTAMINATION,
        random_state=RANDOM_STATE,
        n_jobs=-1
    )
    pipe = Pipeline([('pre', preprocessor), ('iso', iso)])

    console.print("\n[bold blue]🔧 A treinar IsolationForest (aprendendo o comportamento normal)...[/bold blue]")
    for _ in track(range(10), description="Treino em progresso"):
        time.sleep(0.05)

    pipe.fit(X_train)
    model_file = os.path.join(RESULTS_DIR, f"{MODEL_PREFIX}_{ts}.pkl")
    joblib.dump(pipe, model_file)
    console.print(f"[green]✅ Modelo guardado em:[/green] {model_file}")

    # --- Avaliação ---
    results_csv = os.path.join(RESULTS_DIR, f"resultados_anomalias_{ts}.csv")
    hist_png = os.path.join(RESULTS_DIR, f"hist_scores_{ts}.png")
    cm_png = os.path.join(RESULTS_DIR, f"matriz_confusao_{ts}.png")
    metrics_csv = None
    metrics_text = ""

    if not df_test.empty:
        console.print("\n[bold blue]🧪 A aplicar modelo aos ficheiros de teste...[/bold blue]")
        X_test = df_test.drop(columns=['malicious'], errors='ignore')
        y_true = df_test['malicious'] if 'malicious' in df_test.columns else None

        scores = pipe.decision_function(X_test)
        preds = pipe.predict(X_test)  # 1 = normal, -1 = anómalo

        df_test_res = df_test.copy()
        df_test_res['anomaly_score'] = scores
        df_test_res['pred_raw'] = preds
        df_test_res['anomaly_pred'] = np.where(preds == -1, 1, 0)  # 1 = anómalo, 0 = normal

        df_test_res.to_csv(results_csv, index=False)
        console.print(f"[green]📄 Resultados de anomalias salvos em:[/green] {results_csv}")

        try:
            plot_hist_anomaly_score(scores, hist_png)
            console.print(f"[green]📈 Histograma de scores salvo em:[/green] {hist_png}")
        except Exception as e:
            console.print(f"[yellow]Erro ao gerar histograma: {e}[/yellow]")

        if y_true is not None:
            y_pred = df_test_res['anomaly_pred']
            acc = accuracy_score(y_true, y_pred)
            prec, rec, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='binary', zero_division=0)
            cm = confusion_matrix(y_true, y_pred)
            cr_text = classification_report(y_true, y_pred)

            metrics_csv = os.path.join(RESULTS_DIR, f"metrics_iso_{ts}.csv")
            pd.DataFrame({
                "accuracy": [acc],
                "precision": [prec],
                "recall": [rec],
                "f1": [f1]
            }).to_csv(metrics_csv, index=False)

            plot_confusion_matrix(cm, labels=['Normal (0)', 'Anómalo (1)'], out_path=cm_png)
            console.print(f"[green]✅ Matriz de confusão salva em:[/green] {cm_png}")

            metrics_text = (
                f"Accuracy: {acc:.4f}\n"
                f"Precision: {prec:.4f}\n"
                f"Recall: {rec:.4f}\n"
                f"F1-score: {f1:.4f}\n\n"
                f"Classification Report:\n{cr_text}"
            )

    else:
        console.print("[yellow]⚠️ Nenhum ficheiro de teste encontrado. Apenas o modelo foi treinado e guardado.[/yellow]")

    # --- Gerar relatório HTML ---
    html_path = os.path.join(RESULTS_DIR, f"relatorio_anomalias_{ts}.html")
    save_html_report(
        metrics_text=metrics_text,
        file_list_train=train_files,
        file_list_test=test_files,
        html_path=html_path,
        results_csv_path=results_csv,
        metrics_csv_path=metrics_csv,
        hist_path=hist_png,
        cm_path=cm_png
    )

    console.print(f"\n[green]📘 Relatório HTML gerado em:[/green] {html_path}")
    console.print("[bold green]✅ Processo concluído com sucesso.[/bold green]")

# ------------------- CLI -------------------
def main():
    console.clear()
    console.print(Panel.fit(
        "[bold cyan]🚀 Mod-Sentinel - Deteção de Anomalias (IsolationForest)[/bold cyan]\n"
        "[dim]Treina com tráfego benigno em 'run treino/' e detecta anomalias em 'run teste/'[/dim]",
        border_style="bright_magenta"
    ))
    train_anomaly_detection()

if __name__ == "__main__":
    main()
