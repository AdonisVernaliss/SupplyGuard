# SupplyGuard

[English](README.md) · [Deutsch](README.de.md)

SupplyGuard — самостоятельно разработанный проект для безопасности программной цепочки поставок. Приложение проверяет CycloneDX JSON по сопоставлению полей **BSI TR-03183-2 v2.1.0**, запрашивает известные уязвимости в [OSV](https://osv.dev/) и объединяет результаты в понятный отчёт.

> SupplyGuard выполняет технические проверки по профилю. Это не официальный инструмент сертификации BSI.

## Поддерживаемый профиль

| Параметр | Значение |
| --- | --- |
| Профиль | `BSI TR-03183-2` |
| Версия профиля | `2.1.0` |
| Основа сопоставления | `CycloneDX JSON 1.6` |
| Принимаемые версии CycloneDX | `1.6`, `1.7` |
| Источник уязвимостей | OSV API или детерминированное офлайн-демо |

Профиль объявлен в [`apps/api/app/profile.py`](apps/api/app/profile.py) и возвращается health-методом, каждым анализом и локализованными отчётами. Реализованные правила и ограничения описаны в [`docs/bsi-profile.md`](docs/bsi-profile.md).

## Локальный запуск

Потребуются Python 3.12+, [uv](https://docs.astral.sh/uv/) и Node.js 22+.

```bash
# Терминал 1 — API
cd apps/api
uv sync --dev
uv run uvicorn app.main:app --reload

# Терминал 2 — интерфейс
cd apps/web
npm ci
npm run dev
```

Откройте `http://localhost:5173`. Документация API доступна на `http://localhost:8000/docs`.

Встроенное демо работает без сети. Загруженные SBOM по умолчанию проверяются через OSV; для автономной проверки выберите офлайн-источник.

## Docker

```bash
docker compose up --build
```

Интерфейс: `http://localhost:3000`, API: `http://localhost:8000`.

## Проверки

```bash
cd apps/api
uv run pytest
uv run ruff check .
uv run ruff format --check .

cd ../web
npm run check
npm run build
```

Дополнительная документация: [`docs/architecture.md`](docs/architecture.md) · [`docs/threat-model.md`](docs/threat-model.md)

Лицензия: MIT
