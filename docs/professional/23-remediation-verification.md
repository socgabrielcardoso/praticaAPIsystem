# Reteste de correção

Depois de corrigir um problema:

1. repetir exatamente o caso que falhava;
2. confirmar o novo comportamento;
3. testar o fluxo legítimo;
4. testar uma variação próxima;
5. revisar logs e erros;
6. manter o caso como teste de regressão quando fizer sentido.

Se a correção quebra o fluxo válido ou só bloqueia um payload específico, o problema ainda não foi resolvido direito.
