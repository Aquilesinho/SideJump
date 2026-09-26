# SideJump Server

Backend do SideJump: contas, login, sessões, publicação, listagem, download e exclusão dos próprios níveis.

## Variável obrigatória

`DATABASE_URL`

No Railway, adicione um serviço PostgreSQL ao mesmo projeto e use a `DATABASE_URL` fornecida pelo Railway.

## Local

```bash
pip install -r requirements.txt
uvicorn server:app --reload
```

## Produção

```bash
uvicorn server:app --host 0.0.0.0 --port $PORT
```

## Endpoints

GET `/`
GET `/health`
POST `/account/register`
POST `/account/login`
POST `/account/logout`
GET `/account/me`
GET `/levels`
GET `/levels/mine`
POST `/levels/publish`
GET `/levels/{id}`
DELETE `/levels/{id}`

O servidor aceita `.level` nas versões 1, 2 e 3 e valida o formato antes de publicar.
