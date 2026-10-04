# Pratica API System — notas do projeto

## Finalidade

Centralizar enriquecimento de indicadores de comprometimento usados em análise defensiva.

A aplicação recebe um IOC, consulta as fontes configuradas, normaliza os retornos e monta uma resposta única para facilitar a triagem.

## Componentes

- API com FastAPI;
- cliente HTTP assíncrono;
- validação com Pydantic;
- CLI com Typer;
- saída de terminal com Rich;
- testes com Pytest;
- lint com Ruff;
- execução via Docker.

## Cuidados

Chaves de serviços externos ficam fora do código. Erros de integração precisam ser tratados sem expor segredo e sem transformar indisponibilidade de uma fonte em um veredito incorreto.
