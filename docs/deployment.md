# Despliegue en Kibana

```bash
dac deploy --dry-run     # plan: qué se crearía, actualizaría o desactivaría
dac deploy               # aplica el plan
dac deploy --prune       # borra (en vez de desactivar) las reglas eliminadas del repo
dac deploy --force       # redespliega todo (p. ej. tras rotar la API key)
```

## El repo es la fuente de verdad

`dac deploy` convierte las reglas (igual que `dac convert`) y las compara con las que hay en Kibana con el tag `Detection-as-Code`. **Nunca toca reglas que no lleven ese tag**, como las prebuilt de Elastic o las creadas a mano.

| Acción | Cuándo | Llamada |
|--------|--------|---------|
| `create` | La regla está en el repo y no en Kibana | `POST /api/detection_engine/rules` |
| `update` | Ha cambiado `meta.dac.content_hash` (regla, pipeline o conversión) | `PUT` (reemplazo completo) |
| `drift` | Mismo hash, pero alguien la editó en Kibana (query, índices, severidad, `enabled`…) | `PUT`: se restaura desde el repo |
| `disable` | La regla gestionada ya no está en el repo | `PATCH enabled=false` |
| `delete` | Igual que `disable`, pero con `--prune` | `DELETE` |
| `unchanged` | No hay nada que hacer | — |

- **Es idempotente:** si se ejecuta dos veces seguidas, la segunda da `Kibana is in sync: 8 unchanged`.
- **Un fallo no detiene el resto:** cada regla se aplica por separado y los errores se listan al final (código de salida 1).
- **Las reglas `experimental` se despliegan desactivadas.** Para activarlas se cambia a `status: test` en un PR.

### Ciclo de vida probado contra Kibana 8.17

| Escenario | Resultado |
|-----------|-----------|
| Un analista baja la severidad y desactiva la regla en Kibana | `drift (severity, risk_score, enabled)` → restaurada |
| La regla cambia en el repo | `update (content changed)` → la nueva query está en Kibana |
| Se borra el archivo de la regla | `disable` y, en la siguiente ejecución, `orphan, already disabled` |
| Se recupera el archivo | `drift (enabled)` → reactivada |

## Credenciales

El despliegue usa la API key del usuario `dac_pipeline` (`DAC_API_KEY`), nunca el superusuario. Dos detalles que encontré al probarlo:

- **Una API key sin roles explícitos guarda una foto de los privilegios del usuario en el momento de crearla.** Cuando cambia el rol (por ejemplo, al añadir `winlogbeat-*`, que faltaba), hay que rotarla: `dac lab setup --rotate-key` crea una nueva e invalida las anteriores.
- **Cada regla de Kibana se ejecuta con la key que la creó**, así que después de rotarla hay que hacer `dac deploy --force`. Antes de corregirlo, el estado de ejecución de las reglas lo indicaba: *"may not have the required read privileges to … winlogbeat-\*"*.

## Prueba end to end: `dac lab replay`

```bash
dac lab replay otrf_psh_lsass_memory_dump_comsvcs splunk_t1482_art_sysmon ...
dac lab replay --clean
```

Reproduce datasets de test en `winlogbeat-dac-replay-<id>`, un índice que las reglas desplegadas ya leen. Comprime sus timestamps en los últimos 2 minutos, manteniendo el orden de los eventos, para que la captura entera caiga en la ventana de las reglas (`from: now-6m`). En la siguiente ejecución, las reglas generan **alertas reales en Kibana → Security → Alerts**.

Resultado al reproducir 6 datasets (comsvcs, nltest, schtasks, PsExec, launcher VBS y wevtutil): **14 alertas de 7 reglas**, el mismo número de hits que da `dac test` sobre esos datasets. Las 8 reglas quedan con estado de ejecución `succeeded`. La octava (Run Key) no generó alerta porque su dataset no se reprodujo.

| Regla | Alertas |
|-------|--------:|
| Domain Trust and Domain Controller Discovery via Nltest | 3 |
| Windows Event Log Cleared via Command Line | 3 |
| LSASS Dump via Comsvcs.dll MiniDump | 2 |
| PowerShell Encoded Command Execution | 2 |
| Scheduled Task Created With Suspicious Action | 2 |
| PsExec Service Installation | 1 |
| Suspicious LSASS Process Access | 1 |

## Desde GitHub Actions

`.github/workflows/deploy.yml` se lanza a mano (*Run workflow*) y por defecto solo hace `--dry-run`. El lab es local, así que necesita un **runner self-hosted** en la máquina del lab, con las etiquetas `self-hosted, dac-lab`, y los secretos `DAC_KIBANA_URL`, `DAC_ES_URL` y `DAC_API_KEY` en el environment `lab`. Si no hay runner, el job se queda en cola y el CI no depende de él.
