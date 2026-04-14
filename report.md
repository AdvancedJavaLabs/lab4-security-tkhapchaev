# Отчёт по лабораторной работе №4

## Этап 1 — Asset Inventory

| Актив | Тип | Ценность | Примечание |
|---|---|---|---|
| Данные пользователей (`userId`, `userName`) | Данные | Высокая | Используются в HTML-ответе; возможны XSS-атаки и утечка профилей |
| Данные сессий (`loginTime`, `logoutTime`, агрегаты активности) | Данные | Высокая | Влияют на аналитические метрики и бизнес-решения |
| Файловая система сервера | Инфраструктура | Критическая | Через `/exportReport` можно записывать файлы на сервер |
| Внутренняя сеть / локальные ресурсы окружения | Инфраструктура | Критическая | Через `/notify` сервер выполняет запросы к произвольным URL |

Наиболее критичные активы: файловая система сервера и внутренняя сеть окружения. Их компрометация позволяет выйти за рамки обычной логики API и воздействовать на инфраструктуру.

---

## Этап 2 — Threat Modeling (STRIDE)

| Категория | Применимо | Источник угрозы | Поверхность атаки | Потенциальный ущерб |
|---|---|---|---|---|
| **S**poofing | Да | Внешний неаутентифицированный клиент | Все endpoint'ы с `userId` | Работа с чужими данными по произвольному `userId` |
| **T**ampering | Да | Внешний клиент | `/recordSession`, `/exportReport` | Искажение метрик, запись файлов вне целевой директории |
| **R**epudiation | Да | Любой клиент | Все endpoint'ы | Отсутствие аудита: сложно доказать факт и источник действий |
| **I**nformation Disclosure | Да | Внешний клиент | `/userProfile`, обработка ошибок с `e.getMessage()`, `/notify` | Утечка внутренних деталей приложения и данных |
| **D**enial of Service | Да | Внешний клиент | Все endpoint'ы | Нет rate limit/квот, можно перегружать API запросами |
| **E**levation of Privilege | Частично | Внешний клиент | `/notify`, `/exportReport` | Переход от логики API к доступу к внутренним ресурсам сервера |

---

## Этап 3 — Ручное тестирование

Проверены все endpoint'ы:

| Endpoint | Проверка | Результат |
|---|---|---|
| `POST /register` | Спецсимволы в `userName` | Payload сохраняется и попадает в HTML-профиль |
| `POST /recordSession` | `logoutTime < loginTime` | Невалидная сессия принимается |
| `GET /totalActivity` | Значение после tampering-сессии | Возвращается отрицательное время активности |
| `GET /inactiveUsers` | Границы параметра `days` | Критичных security-дефектов не выявлено |
| `GET /monthlyActivity` | Невалидные входные данные | В ответе раскрываются детали исключений |
| `GET /userProfile` | XSS payload в имени | HTML выдаётся без экранирования |
| `GET /exportReport` | `filename=../...` | Подтверждён path traversal / arbitrary file write |
| `POST /notify` | `callbackUrl` на localhost и `file://` | Подтверждён SSRF и чтение локальных ресурсов |

---

## Этап 4 — Статический анализ Semgrep

### 4.1 Использованные правила

Скачаны и применены registry-паки:

- `p/java`
- `p/owasp-top-ten`
- `p/security-audit`
- `p/secrets`

Дополнительно добавлен Javalin-специфичный пакет:

- `semgrep/rules/p-javalin.yml`

### 4.2 Команды и артефакты

Запуск:

```bash
bash semgrep/run.sh
```

Скрипт формирует:

- `semgrep/results/*.json`
- `semgrep/results/*.sarif`
- `semgrep/results/*.txt`
- `semgrep/results/summary.txt`
- `semgrep/results/rules.sha256`

### 4.3 Итоги Semgrep

Из `semgrep/results/summary.txt`:

- `java findings: 0`
- `owasp-top-ten findings: 0`
- `security-audit findings: 0`
- `secrets findings: 0`
- `javalin findings: 8`

Комментарий: стандартные registry-паки не покрыли уязвимости Javalin-приложения (false negatives для данного стека), поэтому для целевого кода потребовались framework-specific правила.

---

## Этап 5 — Findings

### 🔴 Finding #1 — Stored XSS в `GET /userProfile`

| Поле | Значение |
|---|---|
| **Компонент** | `GET /userProfile` |
| **Тип** | Stored XSS |
| **CWE** | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) — Improper Neutralization of Input During Web Page Generation |
| **CVSS v3.1** | `6.1 MEDIUM (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)` |
| **Статус** | Confirmed |

**Описание:**  
Имя пользователя (`userName`) вставляется в HTML-страницу без экранирования и рендерится браузером как разметка.

**Шаги воспроизведения:**
```text
1. POST /register?userId=evil&userName=<script>alert(1)</script>
2. GET /userProfile?userId=evil
3. Ожидаемый результат: спецсимволы экранируются.
   Фактический результат: payload возвращается в HTML как есть.
```

**Влияние:**  
Выполнение JavaScript в браузере жертвы, кража токенов/данных сессии, фишинговые сценарии.

**Рекомендации по исправлению:**  
Экранировать пользовательские данные (`StringEscapeUtils.escapeHtml4`), добавить CSP, не строить HTML конкатенацией строк.

**Security Test Case:**  
`src/test/java/ru/itmo/testing/lab4/pentest/XssPentestTest.java`

---

### 🔴 Finding #2 — Path Traversal в `GET /exportReport`

| Поле | Значение |
|---|---|
| **Компонент** | `GET /exportReport` |
| **Тип** | Path Traversal / Arbitrary File Write |
| **CWE** | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) — Improper Limitation of a Pathname to a Restricted Directory |
| **CVSS v3.1** | `8.1 HIGH (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)` |
| **Статус** | Confirmed |

**Описание:**  
`filename` напрямую конкатенируется с `REPORTS_BASE_DIR`, отсутствуют нормализация пути и проверка выхода за границы каталога.

**Шаги воспроизведения:**
```text
1. POST /register?userId=ptr_user&userName=Alice
2. GET /exportReport?userId=ptr_user&filename=../outside.txt
3. Ожидаемый результат: 400/403 и отказ в записи.
   Фактический результат: файл создаётся вне /tmp/reports.
```

**Влияние:**  
Запись файлов в произвольный путь, подмена локальных файлов приложения.

**Рекомендации по исправлению:**  
`Path.normalize()` + проверка `target.startsWith(baseDir)`, whitelist имени файла, запрет `..`, `/`, `\`.

**Security Test Case:**  
`src/test/java/ru/itmo/testing/lab4/pentest/PathTraversalPentestTest.java`

---

### 🔴 Finding #3 — SSRF в `POST /notify`

| Поле | Значение |
|---|---|
| **Компонент** | `POST /notify` |
| **Тип** | Server-Side Request Forgery |
| **CWE** | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) — Server-Side Request Forgery |
| **CVSS v3.1** | `8.6 HIGH (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L)` |
| **Статус** | Confirmed |

**Описание:**  
`callbackUrl` принимается от клиента и используется для исходящего соединения сервера без allowlist/denylist.

**Шаги воспроизведения:**
```text
1. POST /register?userId=ssrf_http&userName=Alice
2. POST /notify?userId=ssrf_http&callbackUrl=http://localhost:<port>/secret
3. Ожидаемый результат: блокировка внутренних URL.
   Фактический результат: сервер возвращает ответ внутреннего сервиса.
```

Дополнительно подтверждено чтение локального файла через `file://...`.

**Влияние:**  
Доступ к внутренним сервисам и локальным ресурсам от имени сервера.

**Рекомендации по исправлению:**  
Разрешать только доверенные HTTPS-хосты, блокировать `localhost`/private ranges и схему `file://`, вынести egress-контроль на сетевой уровень.

**Security Test Case:**  
`src/test/java/ru/itmo/testing/lab4/pentest/SsrfPentestTest.java`

---

### 🟠 Finding #4 — Tampering аналитики через `POST /recordSession`

| Поле | Значение |
|---|---|
| **Компонент** | `POST /recordSession`, `GET /totalActivity` |
| **Тип** | Improper Input Validation (Business Logic Abuse) |
| **CWE** | [CWE-20](https://cwe.mitre.org/data/definitions/20.html) — Improper Input Validation |
| **CVSS v3.1** | `7.5 HIGH (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N)` |
| **Статус** | Confirmed |

**Описание:**  
Валидация порядка времени отсутствует: допускается `logoutTime < loginTime`, что даёт отрицательную длительность.

**Шаги воспроизведения:**
```text
1. POST /register?userId=tamper_user&userName=Alice
2. POST /recordSession?userId=tamper_user&loginTime=2026-01-02T12:00:00&logoutTime=2026-01-02T11:00:00
3. GET /totalActivity?userId=tamper_user
4. Ожидаемый результат: запрос отклоняется как невалидный.
   Фактический результат: Total activity: -60 minutes.
```

**Влияние:**  
Подмена аналитики и искажение отчётов/метрик.

**Рекомендации по исправлению:**  
Проверять `logoutTime.isAfter(loginTime)` и возвращать `400` для невалидных интервалов.

**Security Test Case:**  
`src/test/java/ru/itmo/testing/lab4/pentest/ActivityTamperingPentestTest.java`

---

### 🟠 Finding #5 — Information Disclosure через сообщения об ошибках

| Поле | Значение |
|---|---|
| **Компонент** | `POST /recordSession`, `GET /monthlyActivity`, `GET /exportReport`, `POST /notify` |
| **Тип** | Information Exposure Through Error Messages |
| **CWE** | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) — Information Exposure Through an Error Message |
| **CVSS v3.1** | `5.3 MEDIUM (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)` |
| **Статус** | Confirmed |

**Описание:**  
В клиентский ответ включается `e.getMessage()`, что раскрывает внутренние детали исключений.

**Шаги воспроизведения:**
```text
1. POST /recordSession?userId=u1&loginTime=not-a-date&logoutTime=still-not-a-date
2. Ожидаемый результат: нейтральная ошибка без внутренних деталей.
   Фактический результат: "Invalid data: Text 'not-a-date' could not be parsed..."
```

**Влияние:**  
Упрощение разведки для атакующего и повышение точности последующих атак.

**Рекомендации по исправлению:**  
Возвращать клиенту унифицированные сообщения об ошибке, технические детали писать только в серверный лог.

**Security Test Case:**  
`src/test/java/ru/itmo/testing/lab4/pentest/ErrorDisclosurePentestTest.java`

---

## Привязка findings к Semgrep

Файл: `semgrep/results/javalin.json`

- `semgrep.rules.javalin.input-validation.session-order` — `UserAnalyticsController.java:67`
- `semgrep.rules.javalin.error-disclosure.exception-message` — `74`, `115`, `163`, `189`
- `semgrep.rules.javalin.xss.user-profile` — `139`
- `semgrep.rules.javalin.path-traversal.export-report` — `154`
- `semgrep.rules.javalin.ssrf.notify` — `181`

---

## Добавленные security test cases

- `src/test/java/ru/itmo/testing/lab4/pentest/XssPentestTest.java`
- `src/test/java/ru/itmo/testing/lab4/pentest/PathTraversalPentestTest.java`
- `src/test/java/ru/itmo/testing/lab4/pentest/SsrfPentestTest.java`
- `src/test/java/ru/itmo/testing/lab4/pentest/ActivityTamperingPentestTest.java`
- `src/test/java/ru/itmo/testing/lab4/pentest/ErrorDisclosurePentestTest.java`

Проверка:

```bash
./gradlew test
```

Результат: все security-тесты проходят, уязвимости воспроизводятся стабильно.
