# Informe de cobertura

```bash
dac test        # genera build/test-report.json
dac coverage    # → build/site/ (abrir build/site/index.html)
```

`dac coverage` cruza las reglas (sus tags de ATT&CK) con el resultado de `dac test` y los casos de test. Sin informe de tests también funciona, pero entonces todas las técnicas salen como "sin tests".

## Qué genera

| Archivo | Contenido |
|---------|-----------|
| `index.html` | Informe con métricas (reglas, técnicas, detection rate, precisión, eventos), matriz ATT&CK Enterprise, tabla de reglas, *backlog* de detección, falsos positivos aceptados y datasets. Es autónomo: sin dependencias externas, con tema claro y oscuro, y se adapta al móvil. |
| `layer.json` | Capa del **ATT&CK Navigator** (layer 4.5). Cada técnica va coloreada según su estado y enlaza a sus reglas en el repo. Se abre desde el botón *Open in ATT&CK Navigator* del informe. |
| `coverage.json` | El modelo completo, legible por máquina. |
| `badges/*.json` | Endpoints de [shields.io](https://shields.io/badges/endpoint-badge) para los badges del README. |
| `test-report.json` | Copia del informe de `dac test` con el que se generó. |

## Estados de una técnica

Si una técnica tiene varias reglas, manda el peor estado:

| Estado | Cuándo |
|--------|--------|
| 🔴 Failing | Alguna regla de la técnica falla sus tests |
| 🟢 Tested | Al menos una regla (no experimental) pasa sus tests |
| 🟡 Rule without tests | Hay regla, pero sin caso de test o sin resultado |
| 🔵 Experimental | Solo hay reglas con `status: experimental` |

**Cobertura por táctica:** técnicas padre de la táctica con al menos una regla (propia o en alguna de sus subtécnicas) / total de técnicas padre activas en ATT&CK v20.1. El orden de las tácticas sale del objeto `x-mitre-matrix` del bundle STIX.

## Backlog de detección

Los `known_gaps` de los casos de test se muestran como backlog: variantes del ataque que están en el corpus y que ninguna regla detecta todavía, cada una con su explicación. El backlog es la lista de las próximas reglas a escribir.

## Publicación

En cada push a `main`, el job *Detection tests* del CI ejecuta `dac test` y `dac coverage`, y el job *Publish coverage report* lo despliega en **GitHub Pages**. En los PR, el informe se puede descargar como artefacto `coverage-site` para revisarlo antes del merge.

> Requisito, una sola vez: *Settings → Pages → Build and deployment → Source: **GitHub Actions***.
