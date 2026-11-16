# Conversión Sigma → Elastic

```bash
dac convert                    # → build/rules.ndjson (importable en Kibana)
dac convert --show             # muestra además cada consulta EQL
dac convert --index dac-test-* # cambia los índices (lo usan los tests)
```

## Flujo

```
regla Sigma ──► pipeline ecs_windows (pySigma) ──► pipeline dac_ecs_windows.yml ──► backend EQL
                 mapeo de campos a ECS               condiciones por logsource         consulta
                                                                                        │
     pipelines/elastic_targets.yml ──► índices, severidad, intervalo ──► regla Detection Engine
     ATT&CK v20.1 (cache)          ──► threat (táctica → técnica → subtécnica)       (ndjson)
```

## Decisiones

**EQL en lugar de Lucene.** En EQL, los operadores `:` y `like~` comparan sin distinguir mayúsculas de forma nativa, incluso sobre `keyword`. Es justo la semántica de Sigma. Con Lucene, un `*\RUNDLL32.EXE` no encuentra `rundll32.exe` (lo comprobé en la Fase 1), y para corregirlo habría que pasar los valores a minúsculas en la conversión.

**La regla de Elastic se construye en el código.** El formato `siem_rule` del backend sigue el esquema de *alerting* (`params` en camelCase y `rule_type_id: siem.queryRule` también para EQL), no el de importación del Detection Engine. Además pone `license: DRL` y escribe las tácticas como `Credential-Access`. Del backend solo se usa la consulta. El resto lo genera `dac/convert.py`:

| Campo | Origen |
|-------|--------|
| `rule_id` | `id` de Sigma (estable, para que el deploy sea idempotente) |
| `severity` / `risk_score` | `level` según la tabla de `elastic_targets.yml` (mismos valores que las reglas prebuilt de Elastic) |
| `index` | Primer target cuyo `logsource` coincide |
| `threat` | Tags ATT&CK resueltos con la versión fijada (nombres e IDs de la v20.1) |
| `enabled` | `false` si `status: experimental` (staging) |
| `note` | Guía de triaje: descripción, falsos positivos y enlace a la regla en el repo |
| `meta.dac.content_hash` | SHA-256 del contenido. El deploy lo usa para detectar cambios. |

**Condiciones de logsource.** `ecs_windows` mapea los campos, pero no restringe el tipo de evento, así que todas las consultas salían como `any where …` sin filtrar. `pipelines/dac_ecs_windows.yml` añade `event.category`/`event.type` (process_creation) o el canal de Sysmon con `event.code` (process_access, registry_set).

**Regex.** La regex de Elasticsearch (sintaxis Lucene) está **anclada implícitamente** y **no admite `(?i)`**. pySigma añade `(?i)` a toda regex que no distingue mayúsculas: la consulta se acepta, pero no encuentra nada nunca. En el lab:

| Consulta EQL | Resultado |
|--------------|-----------|
| `regex~ "(?i)^%systemroot%\\\\[a-z]{8}\\.exe$"` | 0 (silenciosamente rota) |
| `regex~ "(?i)%systemroot%\\\\[a-z]{8}\\.exe"` | 0 |
| `regex~ "%systemroot%\\\\[a-z]{8}\\.exe"` | **1** ✔ |

Por eso la conversión elimina `(?i)` (`regex~` ya no distingue mayúsculas) y `dac validate` rechaza las regex con `^`, `$` o flags inline.

**Snapshots.** `tests/unit/snapshots/eql/*.eql` guarda la consulta de cada regla. Cualquier cambio en una regla, en un pipeline o en la versión de pySigma aparece como diff en el PR. Para regenerarlos de forma intencionada: `DAC_UPDATE_SNAPSHOTS=1 pytest tests/unit/test_convert.py`.
