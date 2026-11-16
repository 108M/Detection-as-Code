# Tests de detección

```bash
dac datasets fetch     # descarga y verifica (sha256) los datasets de tests/datasets/sources.yml
dac test               # indexa los datasets, ejecuta cada regla (EQL) y evalúa los casos
dac test --reload      # fuerza a reindexar todo
```

Necesita un Elasticsearch: el lab local (`dac lab setup`) o, en CI, un *service container*. El resultado queda en `build/test-report.json` y, en GitHub Actions, también en el resumen del job.

## Cómo funciona

```
sources.yml ──► descarga fijada a un commit + sha256 ──► .cache/datasets/raw (solo originales)
                                                              │
                     parser (OTRF JSON · Windows XML · WinEventLog clásico)
                                                              │
                     normalize.py: ECS como las integraciones Windows de Elastic
                                                              │ (en memoria)
                     un índice por dataset: dac-test-<id>  ◄──┘
                                                              │
          cada regla convertida (EQL) ──► dac-test-* ──► hits por dataset ──► caso de test
```

**Cada regla se ejecuta contra todos los datasets.** Las capturas incluyen horas de actividad normal de Windows (svchost, actualizaciones, el agente de Azure, Splunk, Ansible…). Así, cualquier hit en un dataset que el caso no espera cuenta como **falso positivo**: el ruido de fondo hace de corpus benigno.

## Casos de test

`tests/cases/<nombre-de-la-regla>.yml`:

```yaml
detects:                  # tiene que disparar (si no, el test falla)
  - dataset: otrf_empire_launcher_vbs
    min_hits: 1
also_detects:             # otra actividad maliciosa real que también detecta (no es FP)
  - dataset: otrf_empire_run_keys_standard_user
    reason: Empire stager (powershell -enc) ...
known_gaps:               # variante de la técnica que NO detecta (gap documentado)
  - dataset: otrf_empire_psexec_dcerpc_tcp_svcctl
    reason: ...
accepted_false_positives: # ruido benigno conocido: cuenta como FP, falla si supera el presupuesto
  - dataset: splunk_t1070_001_art_sysmon
    max_hits: 37
    reason: Ansible over WinRM ...
max_false_positives: 0    # hits en cualquier otro dataset
```

El grader avisa también de lo que se queda obsoleto: si un `known_gap` empieza a dar hits ("gap closed? move it to detects") o si un `also_detects` deja de darlos.

## Métricas

| Métrica | Definición |
|---------|------------|
| Detection rate | Datasets `detects` detectados / esperados |
| FP hits | Hits en datasets no esperados + `accepted_false_positives` |
| Alert precision | TP hits / (TP hits + FP hits): qué parte de las alertas merece la pena mirar |

## Hallazgos al construir los tests

Esta sección recoge cómo cambiaron las reglas al probarlas contra datos reales, que es el sentido de hacer detection-as-code.

- **Ansible es el falso positivo clásico de `-EncodedCommand`.** En el dataset de Atomic Red Team de Splunk, los 37 hits de la regla de PowerShell codificado son la orquestación del Attack Range: `winrshost.exe` → `PowerShell -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -EncodedCommand` con el *exec wrapper* de Ansible (decodificado: `&chcp.com 65001 > $null $exec_wrapper_str ...`, `"Reboot initiated by Ansible"`). Es ruido benigno típico en cualquier empresa que usa gestión de configuración. Se trata con una excepción de entorno (host o cuenta de servicio de Ansible), no metiéndolo en la regla genérica, y queda documentado con un presupuesto de hits.
- **Tuning de `0x1410` en el acceso a LSASS.** Su único hit fuera de los ataques era PowerShell de automatización. Todos los dumpers del corpus (Mimikatz, Dumpert, Task Manager, comsvcs) piden también `0x1010` o `0x1fffff`, así que quité la máscara sin perder ninguna detección.
- **Gap real en el servicio de PsExec.** El módulo psexec de Empire (servicio `Updater`) y el `sc create ARTService` de Atomic usan `ImagePath = cmd /c powershell …`, que no es `PSEXESVC` ni un binario aleatorio estilo Impacket. Queda documentado como `known_gap` y es candidato a regla nueva ("servicio cuyo ImagePath ejecuta un intérprete"). Los otros 20 servicios legítimos del dataset (`lsass.exe`, `dns.exe`, DFS, drivers de Splunk y de Sysmon) confirman que la regex de Impacket no da FP.
- **Datos incompletos, conclusión equivocada.** Llegué a documentar que el borrado de logs de Atomic era invisible (lo atribuía a que el script se pasaba por stdin). En realidad, el parser XML descartaba los eventos de varias líneas, y un índice cargado a medias se estaba reutilizando como válido. Lo corregí: los registros se separan por `</Event>` y el fingerprint del índice solo se escribe al final de una carga completa. Con eso, la regla detecta tanto `wevtutil cl System` como el bucle de `Clear-EventLog`.

## Datasets y antivirus

Los datasets contienen telemetría de ataques reales: el stager de Empire en Base64 y líneas de comandos de volcado de LSASS. **Windows Defender los marca** (`Trojan:PowerShell/Boxter`, `VirTool:PowerShell/Empire.gen!A`) aunque solo son logs. Por eso:

- Nada se sube al repo. Se descargan desde un commit fijado y se verifican con sha256.
- La telemetría normalizada **nunca se escribe en disco**: va en streaming a Elasticsearch, que guarda sus datos dentro de la VM de Docker.
- Los casos de test y la documentación evitan las líneas de comandos literales de volcado de credenciales.
- En una estación Windows, si Defender pone en cuarentena algún original, la opción es excluir `.cache\datasets` o ejecutar `dac test` desde WSL. En CI (Linux) no pasa.

## Fuentes

| Fuente | Licencia | Formato |
|--------|----------|---------|
| [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) | MIT | JSON plano (exportadores NXLog/Logstash, con mayúsculas y minúsculas mezcladas en el canal) |
| [Splunk attack_data](https://github.com/splunk/attack_data) | Apache-2.0 | XML de Windows (multilínea) y WinEventLog clásico `key=value` (los campos de 4688/7045 se extraen del `Message`) |
