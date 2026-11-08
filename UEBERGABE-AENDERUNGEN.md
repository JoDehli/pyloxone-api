# Übergabe: Änderungen an pyloxone-api

Stand: 2026-11-08. Dieses Dokument beschreibt nur die Änderungen am Projekt
pyloxone-api. Es ergänzt `HANDOVER-pyloxone-api.md`, das den Auftrag und die
Prioritäten enthält. Die Punkte dort sind hier mit Nummern (4.x) referenziert.

## 1. Ergebnis

- Tests: **285 bestanden**, 3 übersprungen (Online-Tests, Standard `-m 'not online'`).
  Vor den Änderungen: 232 bestanden.
- Neue Testdateien: 5, siehe Abschnitt 4.
- **Nichts committet.** Alle Änderungen liegen im Arbeitsverzeichnis.
- Live am Gerät ist nichts geprüft. Alle neuen Pfade sind nur mit Mocks getestet.

## 2. Geänderte Dateien

| Datei | Änderung |
|---|---|
| `src/pyloxone_api/connection.py` | Entpolsterung, Backoff für 4007/4008, `check_token()`, Preflight, `local_only`, `token_store`-Anbindung, Doku von `kill_token()` |
| `src/pyloxone_api/const.py` | `CMD_CHECK_TOKEN`, `CMD_GET_API_CONFIG`, `TOKEN_MIN_REMAINING_SECONDS` |
| `src/pyloxone_api/exceptions.py` | `LoxoneNoEventSlotsError`, `LoxoneRemoteAccessDeniedError` |
| `src/pyloxone_api/token_store.py` | **neu**: Protokoll `TokenStore`, Prüffunktionen |
| `src/pyloxone_api/__init__.py` | Export von `TokenStore` |
| `README.md` | Usage-Beispiel korrigiert, neuer Abschnitt zum Token-Speichern |
| `docs/TOKEN-STORE.md` | **neu**: Anleitung zum Token-Speichern mit Beispiel |
| `docs/CALLBACKS.md` | Zeile für `token_store` |
| `tests/test_connection_unit.py` | Platzhalter `admin` durch `example-user` ersetzt (2 Zeilen) |
| `tests/test_live_device.py` | **neu**: Gerätetest für Handover 4.3, standardmäßig übersprungen |
| `tests/test_live_killtoken.py` | **neu**: Live-Probe für Handover 4.7, standardmäßig übersprungen |
| `tests/test_authwithtoken_rejection.py` | **neu**: 404 bei `authwithtoken` als Token-Ablehnung |

## 3. Änderungen je Thema

### 3.1 Tolerante Entpolsterung (Handover 4.2)
- `_decrypt` ruft `_strip_padding()` auf. Gültiges PKCS#7 wird entfernt, sonst
  werden nachgestellte Nullbytes entfernt. Eine Null-gepolsterte Antwort wirft
  keinen `ValueError` mehr.
- Senden bleibt bei PKCS#7 (Entscheidung offen, siehe 5.1).
- Bekannte Grenze, im Code dokumentiert: Klartext, der mit gültigen
  Steuerbytes endet, wird gekürzt. Bei Loxone-Textantworten kommt das nicht vor.
- Tests: `tests/test_decrypt_padding.py` (8 Tests).

### 3.2 4007 und 4008 mit normaler Wartezeit (Handover 4.4, geändert)
- Zuerst war eine feste Wartezeit von 300 s ±20 % vorgesehen. Das ist zurückgenommen:
  Es war nicht belegt, dass sofortige Wiederholungen bei 4007 schaden, und nach einem
  Update dauerte die Wiederverbindung bis zu fünf Minuten. Vorher kam sie nach
  spätestens einer Minute zurück.
- Jetzt gilt für 4007, 4008 und die Keine-Slots-Ausnahme der normale Backoff:
  1 s, 2 s, 4 s … höchstens 60 s, mit ±20 % Jitter. Das entspricht dem Verhalten
  vor den Änderungen.
- Geplant, aber nicht umgesetzt: bei 4008 vor dem Wiederholen `hasEventSlots` über
  `jdev/cfg/api` abfragen.
- Keine Änderung an 4003 und 4006 (fatal, Test `test_fatal_codes_raise_unauthorised`).
- Offen: 901 ist nicht behandelt (Entscheidung, siehe 5.3).
- Tests: `tests/test_close_codes_backoff.py` (5 Tests).

### 3.3 `check_token()` (Handover 4.6)
- Sendet `jdev/sys/checktoken/<Klartext-Token>/<Benutzer>` verschlüsselt.
- Rückgabe: `True` bei Code 200, sonst `False`, auch bei 401, 400 und Timeout.
- Ein 401 eskaliert **nicht** zu `LoxoneUnauthorisedError`. Ein ungültiges
  Token ist eine Antwort, kein Sitzungsfehler.
- Vor dem Login: `LoxoneTokenError`, nichts wird gesendet.
- Antwort über `_checktoken_waiter`. Ein Timeout entfernt den Waiter, damit
  späte Antworten nichts erfüllen. `checktoken` steht in `_AUTH_COMMANDS`.
- Tests: `tests/test_check_token.py` (9 Tests).

### 3.4 Preflight über `jdev/cfg/api` (Handover 4.9)
- `_check_event_slots()` liest `hasEventSlots` vor dem Strukturabruf in `open()`.
  - `false`: `LoxoneNoEventSlotsError` (ist eine `LoxoneConnectionError`,
    wird wiederholt, mit dem langen Wait aus 3.2).
  - Fehlgeschlagene Abfrage oder unlesbare Antwort: kein Urteil, es geht weiter.
- `local` kommt weiterhin aus `apiKey`. Es gibt kein zweites `local`-Feld.
- Neuer Konstruktor-Parameter `local_only: bool = False`. Bei `True` und einem
  entfernten Miniserver wirft `_check_local_only()` `LoxoneRemoteAccessDeniedError`.
  Diese Ausnahme ist endgültig und wird von `run()` nicht wiederholt.
- Tests: `tests/test_preflight_cfg.py` (9 Tests).

### 3.5 `killtoken`-Doku (Handover 4.7)
- Die Docstring von `kill_token()` beschreibt jetzt: Die Spezifikation sagt, ein
  gekilltes Token ist nicht mehr verwendbar. Der Live-Probe von 2026-11-08 (siehe
  Abschnitt 5, Punkt 5) hat das nicht widerlegt. Der frühere Befund „Token bleibt
  gültig“ ist nicht reproduziert.
- Das Verhalten von `kill_token()` selbst ist unverändert.

### 3.6 Token-Store-Hook (Handover 4.8)
- Neu: `token_store=` am Konstruktor. Ein Objekt mit `load()` und
  `save(token)`. Die Bibliothek schreibt keine Dateien.
- `save(dict)` nach jedem Login und jedem Refresh (über `_signal_token_changed`).
  `save(None)` bei `reset_token()`.
- `load()` einmal im Konstruktor. Die Bibliothek nutzt das Token nur, wenn:
  - die Daten vollständig und gültig sind (Token, `valid_until`, `hash_alg`),
  - `binding` (`url`, `port`, `user`) genau zum Verbindungsaufbau passt,
  - mehr als `TOKEN_MIN_REMAINING_SECONDS` = 100 s Restlaufzeit übrig sind.
- Sonst beginnt die Verbindung ohne Token und meldet sich mit dem Passwort an.
- Fehler in `load()` und `save()` werden als WARNING geloggt, nie geworfen.
- `token=` und `token_store=` zusammen: `ValueError`.
- `token=` und `token_change_callback` funktionieren unverändert.
- Der Binding-Wert wird bei der Konstruktion festgehalten. Ein Wechsel auf die
  Remote-URL in `open()` ändert ihn nicht.
- Tests: `tests/test_token_store.py` (18 Tests).

### 3.6a Ablehnung des Tokens bei `authwithtoken` (Handover 8)
- Antwort 404 (unbekanntes oder gekilltes Token) wird wie 401 behandelt:
  Token verwerfen, Neuverbindung mit Passwort. Vorher wurde 404 ignoriert, und die
  Verbindung blieb ohne Fehler unauthentifiziert.
- Andere Codes (z. B. 500) verwerfen das Token nicht.
- Konstante `TOKEN_REJECTED_CODES = {401, 404}` in `connection.py`. Gemessen ist 401
  für ein gekilltes Token, 404 ist nur aus Handover 8 übernommen.
- Tests: `tests/test_authwithtoken_rejection.py` (4 Tests).

### 3.7 Doku
- `docs/TOKEN-STORE.md`: Protokoll, Format des Token-Dicts, Gültigkeitsregeln,
  ein Beispiel mit JSON-Datei, Hinweis zur Migration. Das Beispiel wurde ausgeführt
  (Dateirechte 0600, Laden, Ablehnung bei anderem Port, Löschen beim Reset).
- README: Das Usage-Beispiel hatte eine falsche Argumentreihenfolge. Korrigiert.
  Neuer Abschnitt und Link zur Token-Doku.
- Im Dokument steht nur `example-user` als Platzhalter, keine IP des Nutzers.

## 4. Neue Testdateien

| Datei | Tests | Thema |
|---|---|---|
| `tests/test_decrypt_padding.py` | 8 | Entpolsterung |
| `tests/test_close_codes_backoff.py` | 5 | normaler Backoff für 4007, 4008, 1006 |
| `tests/test_check_token.py` | 9 | `check_token()` |
| `tests/test_preflight_cfg.py` | 9 | Preflight und `local_only` |
| `tests/test_token_store.py` | 18 | Token-Store-Hook |

## 5. Offen (Entscheidungen oder Freigaben)

1. **Gerätetest PKCS#7 beim Senden (Handover 4.3).** Der Test ist vorbereitet,
   aber noch nicht gelaufen. Er wird nur gestartet, wenn du ihn freigibst:

   ```bash
   PYLOXONE_LIVE=1 uv run pytest -m online tests/test_live_device.py -s
   ```

   Zugangsdaten kommen aus der Umgebung (`PYLOXONE_TEST_HOST`, `PYLOXONE_TEST_USER`,
   `PYLOXONE_TEST_PASSWORD`) oder aus `.env.live` im Projektordner (git-ignoriert, Modus 0600).
   Der Test gibt sie nicht aus. Er sendet nur
   `checktoken`, also einen Lesebefehl mit PKCS#7-Padding. Geschaltet wird
   nichts, und `killtoken` wird nicht aufgerufen. Der Login legt wie bei jeder
   Verbindung ein Token auf dem Gerät an.
   **Ergebnis (2026-11-08): bestanden.** Das Gerät beantwortet den verschlüsselten
   `checktoken`-Befehl mit PKCS#7-Padding mit Code 200. Zero-Byte-Padding ist für
   diesen Befehlsweg nicht nötig. Der Lauf hat nichts geschaltet und kein Token
   widerrufen.
   Der Test deckt nur den verschlüsselten Befehlsweg über `jdev/sys/enc` ab.
   Ob `jdev/sps/ios` (Secured Commands) PKCS#7 akzeptiert, prüft er nicht.
   Dafür braucht es einen eigenen, ebenfalls harmlosen Lesebefehl.
2. **Token-Store am Gerät testen.** Ein Login mit gespeichertem Token gegen
   ein echtes Gerät steht aus, ebenso der Preflight. `check_token()` ist am
   Gerät bestätigt (siehe 5.1).
3. **901 wie 4007/4008 behandeln? (Handover 4.4, Entscheidung 4).**
4. **Anfrage-Antwort-Modell (Handover 4.10).** Erst Benchmark, dann Entscheidung.
5. **killtoken-Wirkung (Handover 4.7), Ergebnis 2026-11-08.** Der Live-Lauf
   ergab `NO_AUTH`: Mit dem gekillten Token kam innerhalb von 30 s keine
   Anmeldung zustande. Das widerspricht dem früheren Befund, dass das Token
   gültig bleibt. Ein zweiter Lauf am 2026-11-08 mit mitgeschriebenen Codes ergab:
   ein gekilltes Token wird von `authwithtoken` mit **401** abgelehnt (gemessen).
   Der frühere `NO_AUTH` war also genau dieser 401, den die alte Bibliothek
   korrekt verworfen hat. Die Probe hat danach nicht neu verbunden.
   404 ist nicht am Gerät bestätigt. Die Behandlung von 404 (Abschnitt 3.6a)
   beruht nur auf Handover 8 und ist eine Vorsichtsmaßnahme.
   Der Lauf hat ein Token angelegt und gekillt und nichts geschaltet.
6. **Keepalive (Handover 4.12).** Messung eines stillen Sockets steht aus.
7. **4.13 bis 4.15** (Gerätebefehle, OpenTelemetry, TUI) sind optional und nicht begonnen.

## 6. Hinweise für die nächste Session

- Tests laufen mit `uv run --frozen pytest`. Das Projekt hat rund 39
  vorbestehende Lint-Befunde (vor allem E501 und Import-Reihenfolge). Sie sind
  nicht Teil dieser Änderungen. Die neuen Dateien sind lint-sauber.
- Die Warnung `BasicAuth is deprecated` kommt aus `loxone_http_client.py` und
  war schon vorher da.
- `_check_auth_response` eskaliert bei 401. Für `checktoken` wird es bewusst
  nicht benutzt, siehe 3.3.
- `save()` und `load()` des Token-Stores laufen synchron. Langsame Speicher
  sollten in einen Thread ausgelagert werden, das steht in der Doku.
