# Защита ветки `main`

В репозитории добавлены workflow'ы, которые должны стать обязательными проверками
(required status checks) для `main`. Сами проверки уже описаны в
`.github/workflows/build.yml` и `.github/workflows/security.yml`; правила ветки
включаются в настройках GitHub.

## Обязательные проверки

| Проверка в GitHub | Workflow / job | Что ловит |
|---|---|---|
| `Build & unit tests` | `CI` → `build` | Ошибки компиляции, падение unit-тестов, отсутствие классов/ресурсов в jar |
| `Server smoke test` | `CI` → `smoke` | Мод не загружается на выделенном сервере / сервер не стартует |
| `Gradle wrapper validation` | `CI` → `wrapper` | Подменённый `gradle-wrapper.jar` |
| `CodeQL analysis` | `Security` → `codeql` | Потенциальные уязвимости в Java-коде (SAST) |
| `Secret scan` | `Security` → `secrets` | Случайно закоммиченные токены, ключи, пароли |
| `Dependency review` | `Security` → `dependencies` | Новые уязвимые зависимости в PR (только для pull request) |

После первого прогона workflow'ов эти имена появятся в списке доступных проверок.

## Настройка Ruleset для `main`

GitHub → **Settings → Rules → Rulesets → New branch ruleset**.

1. **Target branches**: `main`.
2. **Enforcement status**: `Active`.
3. **Require a pull request before merging**:
   - Required approvals: **1** (для команды — 2);
   - ✅ Dismiss stale pull request approvals when new commits are pushed;
   - ✅ Require review from Code Owners (если добавлен `.github/CODEOWNERS`);
   - ✅ Require conversation resolution before merging.
4. **Require status checks to pass before merging**:
   - ✅ Require branches to be up to date before merging;
   - выбрать проверки из таблицы выше.
5. **Block force pushes** — включить.
6. **Restrict deletions** — включить.
7. **Require linear history** — по желанию (запрещает merge-коммиты).
8. **Require signed commits** — по желанию (если все участники настроили подпись).
9. **Bypass list** — оставить пустым. Не давайте администраторам постоянный bypass:
   аварийный обход должен быть осознанным исключением.

Эквивалент через классический **Branch protection rule**:
Settings → Branches → Add branch protection rule → `main` и те же пункты.

## Дополнительные настройки репозитория

### Actions

Settings → Actions → General:

- **Workflow permissions**: `Read repository contents and packages permissions`
  (в workflow'ах уже стоит `permissions: contents: read`);
- ❌ Allow GitHub Actions to create and approve pull requests;
- **Fork pull request workflows**: требовать approval для внешних контрибьюторов;
- **Actions permissions**: разрешать только нужные actions (или все, но с pinning).

Внешние actions в workflow'ах подключены по major-тегам (`@v4`, `@v3`). Для максимальной
защиты от supply-chain атак закрепите их по полному commit SHA — Dependabot будет
обновлять такие ссылки.

### Безопасность

Settings → Code security:

- ✅ **Secret scanning** + **Push protection** — блокирует коммиты с токенами;
- ✅ **Dependabot alerts** и **Dependabot security updates**
  (конфиг обновлений — `.github/dependabot.yml`);
- ✅ **Code scanning** — результаты CodeQL из workflow'а;
- ✅ **Private vulnerability reporting** — если репозиторий приватный.

`Secret scan` (gitleaks) — дополнительная страховка к встроенному secret scanning.
Для публичных репозиториев лицензия не нужна; для приватных организаций нужен
`GITLEAKS_LICENSE` в secrets, иначе этот job нужно заменить на встроенный secret scanning.

### CODEOWNERS

`.github/CODEOWNERS` уже добавлен и назначает владельцем `@SKUFIKs`. Если состав
мейнтейнеров изменится — обновите файл. После этого включите
«Require review from Code Owners» в ruleset.

### Теги и релизы

Settings → Rules → New tag ruleset → pattern `v*`:

- restrict deletions;
- restrict updates (force push);
- при необходимости — require signed commits.

Для релизного workflow используйте **Environment** с required reviewers, чтобы артефакт
не публиковался без подтверждения.

## Что именно проверяется

### Build & unit tests

```bash
./gradlew build --no-daemon --stacktrace
```

`build` включает `test`, поэтому падение любого unit-теста блокирует merge. После сборки
проверяется содержимое jar: метаданные мода, основные классы и локализации.

### Server smoke test

Поднимает настоящий dev-сервер (`runServer`) с `eula=true`, ждёт строку `Done (` и
проверяет, что в логе нет ошибок загрузки модов. Это ловит ситуации, когда тесты
проходят, а мод не грузится на сервере.

### CodeQL

Анализ `security-and-quality` для Java. Сборка выполняется вручную
(`compileJava`), поэтому NeoForge-проект корректно индексируется.

### Secret scan

gitleaks сканирует всю историю (`fetch-depth: 0`). Он не заменяет GitHub Push Protection,
но ловит то, что уже попало в коммиты.

### Dependency review

Проверяет изменения зависимостей в pull request и падает при high/critical уязвимостях.
Для Gradle-зависимостей GitHub может показывать не всё; поэтому дополнительно включены
Dependabot alerts.

## Дополнительные проверки (по желанию)

- **SpotBugs + FindSecBugs** — дополнительный SAST для Java.
- **OWASP Dependency-Check** — проверка известных CVE (нужен NVD API key, медленно).
- **OSV-Scanner** — быстрый скан уязвимостей; для Gradle потребуется включить
  dependency locking и коммитить `gradle.lockfile`.
- **Spotless/Checkstyle** — единый стиль и запрет опасных конструкций
  (`printStackTrace`, пустые `catch`, случайное логирование секретов).
- **Artifact attestation** (`actions/attest-build-provenance`) — подтверждение
  происхождения релизного jar.
- **Gradle dependency verification** (`verification-metadata.xml`) — защита от подмены
  зависимостей.

## Как воспроизвести проверки локально

```bash
./gradlew build --no-daemon --stacktrace

# smoke-тест сервера
mkdir -p run
echo "eula=true" > run/eula.txt
./gradlew runServer --no-daemon
# дождаться "Done (" и остановить сервер
```

На Windows с кириллицей в пути тесты запускайте через ASCII-junction — см. README.
