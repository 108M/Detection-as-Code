# Convenciones de reglas

`dac validate` comprueba todo lo de este documento. En CI, cualquier error bloquea el PR.

## Ubicación y nombre

```
rules/<producto>/<táctica>/<logsource>_<producto>_<descripción>.yml
```

- Ejemplo: `rules/windows/credential_access/proc_access_win_lsass_suspicious_access.yml`
- Nombre en `snake_case`, en minúsculas y con extensión `.yml`.
- El caso de test va en `tests/cases/<mismo-nombre>.yml`. Si no existe, la regla sale como `untested` (warning, que pasa a error con `--strict`).

## Campos obligatorios

| Campo | Regla |
|-------|-------|
| `title` | Como máximo 110 caracteres y único en el repo |
| `id` | UUID v4, único |
| `status` | `experimental` · `test` · `stable` |
| `description`, `author`, `falsepositives` | No pueden estar vacíos |
| `date` | `YYYY-MM-DD` |
| `level` | `informational` · `low` · `medium` · `high` · `critical` |
| `tags` | Al menos una táctica y una técnica de ATT&CK |
| `logsource`, `detection` | Sintaxis Sigma válida. Las condiciones se resuelven en la validación, no en la conversión. |

## ATT&CK

- La versión está fijada: **ATT&CK v20.1** (`DAC_ATTACK_VERSION`). Para cambiarla basta con un PR.
- Se rechazan las técnicas inexistentes, **revocadas** o **deprecadas**. Si una técnica está revocada, el error indica cuál la sustituye.
- Cada técnica tiene que pertenecer a alguna de las tácticas etiquetadas en la regla.
- En la v20, **Defense Evasion ya no existe**: se divide en `attack.stealth` (TA0005) y `attack.defense-impairment` (TA0112). Por ejemplo, *Clear Windows Event Logs* ha pasado de T1070.001 a **T1685.005**. Las reglas copiadas de repositorios antiguos suelen fallar por esto.

## Validadores de pySigma

Además de lo anterior, se ejecutan los validadores core de pySigma: condiciones colgantes, wildcards en lugar de modificadores, IDs y títulos duplicados, etc. La excepción es `attacktag`, que queda sustituido por la comprobación propia con la versión fijada.

## Cómo añadir una regla

1. Crear el `.yml` en la carpeta de su táctica.
2. Ejecutar `dac validate` hasta que no dé errores.
3. Añadir el caso de test en `tests/cases/` (Fase 4).
4. Abrir el PR. El CI ejecuta lint, `dac validate` y los tests.
