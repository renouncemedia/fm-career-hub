# FM Career Hub

Plataforma web para acompanhar uma carreira no Football Manager: plantel, jogadores, épocas, clubes, transferências, táticas e estatísticas.

## Stack
- Next.js (App Router) + TypeScript
- Supabase (PostgreSQL e autenticação)
- Deploy preparado para Vercel

## Desenvolvimento
```bash
npm install
npm run dev
```

Cria um ficheiro `.env.local` com:
```env
NEXT_PUBLIC_SUPABASE_URL=
NEXT_PUBLIC_SUPABASE_ANON_KEY=
```

> Estado atual: estrutura inicial do projeto. A migração integral do dashboard HTML original e a integração com a base de dados serão feitas nas próximas etapas.
