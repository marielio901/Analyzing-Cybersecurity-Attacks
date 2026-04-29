import nbformat as nbf
import os

NOTEBOOK_METADATA = {
    "kernelspec": {
        "display_name": "Python (CyberSOC venv)",
        "language": "python",
        "name": "python3",
    },
    "language_info": {
        "codemirror_mode": {"name": "ipython", "version": 3},
        "file_extension": ".py",
        "mimetype": "text/x-python",
        "name": "python",
        "nbconvert_exporter": "python",
        "pygments_lexer": "ipython3",
        "version": "3.12.3",
    },
}

def create_notebook(filename, cells):
    nb = nbf.v4.new_notebook()
    nb['cells'] = cells
    nb['metadata'] = NOTEBOOK_METADATA
    
    # Save notebook
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'w', encoding='utf-8') as f:
        nbf.write(nb, f)
    print(f"Created {filename}")

def md_cell(text):
    return nbf.v4.new_markdown_cell(text)

def code_cell(code):
    return nbf.v4.new_code_cell(code)

common_setup = """from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import plotly.io as pio

# Definir o tema escuro para combinar com o CyberSOC
pio.templates.default = "plotly_dark"

def find_data_file(filename="cybersecurity_attacks.csv"):
    for base_path in [Path.cwd(), *Path.cwd().parents]:
        data_path = base_path / filename
        if data_path.exists():
            return data_path
    raise FileNotFoundError(f"Nao encontrei {filename} a partir de {Path.cwd()}")

csv_path = find_data_file()
df = pd.read_csv(csv_path)

# Pre-processamento basico
# Padronizar nomes de colunas e preencher nulos
df.fillna("Unknown", inplace=True)

print(f"Total de registros carregados: {len(df)}")
print(f"Arquivo carregado: {csv_path}")
df.head(3)"""

# ---------------------------------------------------------
# 1. Overview Notebook
# ---------------------------------------------------------
overview_cells = [
    md_cell("# Analise de Dados: Overview\n\nEste notebook apresenta a analise principal (Overview) do CyberSOC, focada nos KPIs globais, taxa de bloqueio e severidade dos eventos."),
    code_cell(common_setup),
    md_cell("## 1. Distribuicao de Severidade\nVisualizando o volume de ataques por severidade (Low, Medium, High, Critical)."),
    code_cell("""severity_counts = df['Severity Level'].value_counts().reset_index()
severity_counts.columns = ['Severity', 'Count']

fig = px.pie(severity_counts, values='Count', names='Severity', 
             title='Distribuicao de Severidade dos Ataques',
             color='Severity', 
             color_discrete_map={'Critical':'#ff4fd8', 'High':'#fb7185', 'Medium':'#fbbf24', 'Low':'#00f5a0'})
fig.show()"""),
    md_cell("> **Insight**: Observando a proporcao de ataques criticos e altos, a equipe do SOC pode ajustar os recursos de triagem. Uma grande quantidade de Low/Medium sugere a necessidade de maior automacao na filtragem inicial."),
    md_cell("## 2. Acoes Tomadas (Action Taken)"),
    code_cell("""action_counts = df['Action Taken'].value_counts().reset_index()
action_counts.columns = ['Action', 'Count']

fig = px.bar(action_counts, x='Action', y='Count', title='Acoes Tomadas pelo Firewall/IDS', 
             color='Action', text_auto=True)
fig.show()"""),
    md_cell("> **Insight**: A relacao entre `Blocked` e `Ignored`/`Logged` reflete a Taxa de Bloqueio (Control Efficacy). Uma baixa taxa de bloqueio requer revisao urgente das regras do firewall."),
]

# ---------------------------------------------------------
# 2. Network Analytics
# ---------------------------------------------------------
network_cells = [
    md_cell("# Analise de Dados: Network Analytics\n\nAnalise focada em trafego de rede, IPs, protocolos e comprimento de pacotes vs score de anomalia."),
    code_cell(common_setup),
    md_cell("## 1. Distribuicao de Protocolos"),
    code_cell("""proto_counts = df['Protocol'].value_counts().reset_index()
proto_counts.columns = ['Protocol', 'Count']

fig = px.pie(proto_counts, values='Count', names='Protocol', hole=0.4, title='Distribuicao de Protocolos de Rede')
fig.show()"""),
    md_cell("## 2. Packet Length vs Anomaly Score"),
    code_cell("""# Selecionando uma amostra para o scatter plot para performance
sample_df = df.sample(min(2000, len(df)))

fig = px.scatter(sample_df, x='Packet Length', y='Anomaly Scores', color='Severity Level',
                 title='Comprimento do Pacote vs Score de Anomalia',
                 hover_data=['Protocol', 'Attack Type'])
fig.show()"""),
    md_cell("> **Insight**: O grafico de dispersao permite identificar clusters de trafego malicioso. Pacotes excepcionalmente grandes com alto Anomaly Score sao fortes indicadores de exfiltracao de dados ou ataques volumetricos (DDoS).")
]

# ---------------------------------------------------------
# 3. Threat Intelligence
# ---------------------------------------------------------
threat_cells = [
    md_cell("# Analise de Dados: Threat Intelligence\n\nMapeamento profundo dos Tipos de Ataque e sua criticidade."),
    code_cell(common_setup),
    md_cell("## 1. Principais Tipos de Ataque"),
    code_cell("""attack_counts = df['Attack Type'].value_counts().head(10).reset_index()
attack_counts.columns = ['Attack Type', 'Count']

fig = px.bar(attack_counts, x='Count', y='Attack Type', orientation='h', title='Top 10 Tipos de Ataque')
fig.update_layout(yaxis={'categoryorder':'total ascending'})
fig.show()"""),
    md_cell("## 2. Heatmap: Tipo de Ataque vs Severidade"),
    code_cell("""heatmap_data = pd.crosstab(df['Attack Type'], df['Severity Level'])

fig = px.imshow(heatmap_data, text_auto=True, aspect="auto",
                title="Heatmap de Criticidade por Tipo de Ataque",
                color_continuous_scale="Viridis")
fig.show()"""),
    md_cell("> **Insight**: O heatmap cruza o vetor de ataque com o nivel de severidade. Se um tipo especifico (ex: Malware) concentra as severidades criticas, ele deve ser a prioridade numero um nas regras de deteccao.")
]

# ---------------------------------------------------------
# 4. Anomaly Detection
# ---------------------------------------------------------
anomaly_cells = [
    md_cell("# Analise de Dados: Anomaly Detection\n\nAnalise do motor de deteccao de anomalias (Anomaly Scores) e distribuicao estatistica."),
    code_cell(common_setup),
    md_cell("## 1. Distribuicao do Anomaly Score"),
    code_cell("""fig = px.histogram(df, x='Anomaly Scores', nbins=50, title='Histograma de Anomaly Scores',
                   color='Severity Level', marginal='box')
fig.show()"""),
    md_cell("> **Insight**: Este histograma com boxplot na margem mostra a concentracao dos escores. Um Threshold ideal deve ser configurado no vale entre a distribuicao normal (trafego benigno) e a cauda direita (anomalias)."),
]

# ---------------------------------------------------------
# 5. Firewall & IDS
# ---------------------------------------------------------
firewall_cells = [
    md_cell("# Analise de Dados: Firewall & IDS\n\nValidacao das regras de seguranca perimetral, bloqueios e alertas IDS."),
    code_cell(common_setup),
    md_cell("## 1. Action Taken by Attack Type"),
    code_cell("""action_attack = pd.crosstab(df['Attack Type'], df['Action Taken']).reset_index()
fig = px.bar(action_attack, x='Attack Type', y=['Blocked', 'Ignored', 'Logged'], 
             title='Eficacia do Firewall por Tipo de Ataque', barmode='group')
fig.show()"""),
    md_cell("> **Insight**: Graficos agrupados mostram claramente onde o Firewall esta falhando (muitos ataques High/Critical sendo 'Ignored' ou 'Logged' em vez de 'Blocked'). Requer correcao imediata nas ACLs.")
]

# ---------------------------------------------------------
# 6. Geo Intelligence
# ---------------------------------------------------------
geo_cells = [
    md_cell("# Analise de Dados: Geo Intelligence\n\nInteligencia geografica de ameacas ciberneticas."),
    code_cell(common_setup),
    md_cell("## 1. Principais Paises/Localidades Ofensores"),
    code_cell("""# Processando Geo-location Data (simulando extracao de paises)
# No dataset padrao, isso pode ser mockado ou misturado, ajustaremos pegando as principais strings
geo_counts = df['Geo-location Data'].value_counts().head(15).reset_index()
geo_counts.columns = ['Location', 'Events']

fig = px.bar(geo_counts, x='Events', y='Location', orientation='h', title='Top 15 Origens de Ataques')
fig.update_layout(yaxis={'categoryorder':'total ascending'})
fig.show()"""),
    md_cell("> **Insight**: O mapeamento de origens pode justificar a criacao de politicas de Geo-Blocking preventivo para locais de alto risco ou sem transacoes de negocios esperadas.")
]

def main():
    doc_dir = "Documentation"
    create_notebook(os.path.join(doc_dir, "01_Overview.ipynb"), overview_cells)
    create_notebook(os.path.join(doc_dir, "02_Network_Analytics.ipynb"), network_cells)
    create_notebook(os.path.join(doc_dir, "03_Threat_Intelligence.ipynb"), threat_cells)
    create_notebook(os.path.join(doc_dir, "04_Anomaly_Detection.ipynb"), anomaly_cells)
    create_notebook(os.path.join(doc_dir, "05_Firewall_IDS.ipynb"), firewall_cells)
    create_notebook(os.path.join(doc_dir, "06_GeoIntelligence.ipynb"), geo_cells)

if __name__ == "__main__":
    main()
