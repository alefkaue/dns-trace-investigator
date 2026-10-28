# Investigação offline de DNS

**Área do portfólio:** [Cybersecurity](https://github.com/alefkaue#cybersecurity) · **Contexto:** Projeto pessoal

Ferramenta pessoal em Python para analisar exportações de consultas DNS e relacionar eventos
a intervalos de concessão DHCP. Não captura tráfego, não consulta servidores externos e não
classifica um padrão suspeito como invasão confirmada.

```console
python -m dns_trace --queries examples/queries.csv --leases examples/leases.csv --out examples/output
python -m unittest discover -s tests -v
```

Python 3.11+, sem dependências externas. O exemplo sintético produz um alerta para revisão.
Os relatórios mantêm hash dos arquivos, linhas de evidência, critérios e ambiguidades.
Rótulos de consultas ficam ocultos por padrão; não use dados reais nos commits públicos.

O README em inglês documenta exportação de PCAP via TShark, entradas, limitações e os comandos
de instalação. Código reconstruído com assistência de IA, validado em dados sintéticos; não representa
experiência profissional de resposta a incidentes.
