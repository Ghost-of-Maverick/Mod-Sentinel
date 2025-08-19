import pandas as pd

# Carregar o ficheiro
df = pd.read_csv("MetroPT3(AirCompressor).csv")

# Converter timestamps
df['timestamp'] = pd.to_datetime(df['timestamp'])

# Selecionar a coluna da temperatura
df = df[['timestamp', 'Oil_temperature']]
df.columns = ['timestamp_original', 'temperatura_original']

# Indexar e ordenar
df.set_index('timestamp_original', inplace=True)
df = df.sort_index()

# Criar indice continuo de 1 em 1 segundo
full_range = pd.date_range(start=df.index.min(), end=df.index.max(), freq='1s')

# Reindexar e interpolar
df_interpolado = df.reindex(full_range).interpolate(method='linear')
df_interpolado.index.name = 'timestamp_novo'

# Reset do indice
df_interpolado.reset_index(inplace=True)
df_interpolado.columns = ['timestamp_novo', 'temperatura_nova']

# Dataset original para comparacao
df_completo = pd.DataFrame({
    'timestamp_original': df.index,
    'temperatura_original': df['temperatura_original'].values
}).reset_index(drop=True)

# Combinar datasets
df_resultado = pd.concat([df_completo, df_interpolado], axis=1)

# Exportar se necessario
df_resultado.to_csv("MetroPT3_interpolado.csv", index=False)
