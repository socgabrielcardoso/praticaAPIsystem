# Pratica API System

Gateway de **IOC enrichment** voltado a Blue Team.

O projeto recebe indicadores de comprometimento e organiza consultas a fontes de Threat Intelligence para devolver uma análise defensiva mais consistente. A ideia é reduzir o trabalho manual de consultar múltiplas fontes e centralizar o resultado em um único fluxo.

## Stack

- Python 3.11+
- FastAPI
- HTTPX
- Pydantic
- Typer
- Rich
- Uvicorn
- Pytest
- Ruff
- Docker

## Objetivos

- receber e validar IOCs
- enriquecer indicadores usando APIs externas configuradas
- normalizar respostas
- apresentar um veredito defensivo
- manter comportamento previsível em erros e timeouts
- permitir uso via API e CLI
- testar integrações sem expor chaves reais

## Instalação

```bash
python -m venv .venv
pip install -e ".[dev]"
```

## Testes

```bash
pytest
```

## Qualidade

```bash
ruff check .
```

## Estrutura

- `src/pratica_api_system/` — aplicação
- `tests/` — testes
- `docs/` — documentação técnica
- `Dockerfile` — execução containerizada
- `.env.example` — referência de configuração sem segredos

## Segurança

Chaves de API e tokens devem ficar fora do Git. Use apenas valores de teste no repositório e variáveis de ambiente para credenciais reais.

## Segurança verificável e evidências

A segurança deste projeto é tratada como processo contínuo, **não como promessa de software invulnerável**:

- [Registro de riscos e superfície de ataque](docs/SECURITY_RISK_REGISTER.md)
- [Plano reproduzível de testes](docs/SECURITY_VALIDATION_PLAN.md)
- [Guia de implantação segura](docs/SECURE_DEPLOYMENT.md)
- [Resposta a incidentes e recuperação](docs/INCIDENT_PLAYBOOK.md)
- [Evidências e estudo de caso para portfólio](docs/PORTFOLIO_EVIDENCE.md)

O workflow `.github/workflows/security-guard.yml` detecta classes de credenciais expostas em arquivos rastreados e executa testes regressivos do detector. **Não substitui SAST, DAST, pentest, proteção de branch, autenticação, revisão humana nem varredura completa do histórico Git.** Verifique o status do CI na revisão que pretende publicar. Use somente dados sintéticos em demonstrações públicas.
