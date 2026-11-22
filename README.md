# FM Career Hub

Aplicação web para gerir uma carreira no Football Manager.

## Funcionalidades nesta versão
- Autenticação Supabase por email e palavra-passe.
- Leitura do plantel já existente na carreira da conta.
- Pesquisa e filtro por estado.
- Criar, editar e retirar jogadores da carreira.
- Snapshots CA/PA para preservar a evolução dos jogadores.
- Importação CSV/JSON com correspondência por nome.
- Exportação CSV e backup JSON.
- Persistência Supabase com Row Level Security.

## Desenvolvimento
1. `npm install`
2. Copia `.env.example` para `.env.local` e preenche as variáveis.
3. `npm run dev`

Variáveis necessárias: `NEXT_PUBLIC_SUPABASE_URL` e `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`.

Nunca coloques uma chave `service_role` ou `secret` no frontend.

## Migração pendente
O parser binário de ficheiros de save `.fm` do dashboard HTML original ainda requer migração e testes específicos por versão do Football Manager.
