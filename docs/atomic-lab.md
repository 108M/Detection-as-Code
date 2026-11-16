# Lab de ataque: capturas propias con Atomic Red Team

Los datasets públicos (OTRF, Splunk) cubren poco y se grabaron con otras configuraciones de Sysmon. Para cada regla nueva generamos **nuestra propia telemetría**: ejecutamos el ataque con Atomic Red Team en una VM Windows 11 instrumentada, exportamos los eventos de ese intervalo y los añadimos al corpus de test.

## La VM como código

`lab/vm/Vagrantfile` (VirtualBox + Vagrant) crea una VM desechable:

| Componente | Versión (fijada) | Para qué |
|------------|------------------|----------|
| Windows 11 Enterprise eval | box `gusztavvargadr/windows-11` 2607.1.0 | Endpoint típico de empresa |
| Sysmon + [sysmon-modular](https://github.com/olafhartong/sysmon-modular) | release `configs-a45dedb13a43` (sha256 verificado); Sysmon con firma de Microsoft verificada | Procesos, acceso a LSASS, registro, red… |
| Auditoría nativa | `provision/telemetry.ps1` | 4688 con línea de comandos, logons, gestión de cuentas, cambios de política |
| PowerShell logging | ScriptBlock (4104) y módulos (4103) | Ver scripts aunque lleguen por stdin o codificados |
| Atomic Red Team | atomics del commit `a0e3f9b`, Invoke-AtomicRedTeam 2.3.0 | Los ataques |

Defender se **desactiva** dentro de la VM (`provision/defender.ps1`). Con él activo, la detección por comportamiento y AMSI mata los tests por su línea de comandos (por ejemplo `mshta javascript:...`) aunque haya exclusiones de ruta, y no queda telemetría de la ejecución real. La protección contra alteraciones no se puede apagar por script. Hay que hacerlo una vez a mano:

1. Abre la VM `dac-win11` en el Administrador de Hyper-V (usuario y contraseña `vagrant`).
2. Ve a Seguridad de Windows > Protección antivirus y contra amenazas > Administrar la configuración > **Protección contra alteraciones: desactivada**.
3. En el host ejecuta `vagrant provision --provision-with defender`.

El canal de Defender se sigue exportando en las capturas.

La **protección de LSA** (LSASS como proceso protegido, PPL) también se desactiva (`provision/lsa.ps1`, que reinicia la VM). Windows 11 22H2+ la trae activa por defecto (`RunAsPPL = 2`). Con ella, `rundll32 comsvcs.dll MiniDump` recibe acceso denegado al abrir `lsass.exe`: no hay volcado ni evento 10 de Sysmon, porque Sysmon solo registra los handles que se conceden. Hay dos capturas del mismo test (T1003.001-2):

- **`lsass_comsvcs_minidump`**: con PPL, el intento se bloquea y solo queda la línea de comandos.
- **`lsass_comsvcs_minidump_noppl`**: sin PPL, el volcado se crea y aparecen el acceso a LSASS (`0x1FFFFF`) y el `.dmp`.

En un equipo real con PPL, la regla de línea de comandos sigue detectando el intento.

```bash
cd lab/vm
vagrant up --provider hyperv   # la primera vez: descarga de la box (~11,5 GB) y aprovisionamiento
vagrant halt                   # apagar
vagrant destroy -f             # empezar de cero (todo es reproducible)
```

### Hyper-V, no VirtualBox (si usas Docker/WSL2)

Con WSL2 o Docker Desktop activos, el hipervisor de Windows ocupa VT-x. VirtualBox cae entonces al modo de compatibilidad NEM (`HM: VT-x is not available, fall back to NEM` en `VBox.log`): Windows 11 arranca, pero **se cuelga en el reinicio de la configuración inicial** (`Guest seems to be unresponsive`). La solución es el proveedor **Hyper-V**, que comparte hipervisor con WSL2 y va a velocidad nativa. Requisitos (una vez, como administrador):

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All   # + reiniciar
Add-LocalGroupMember -SID "S-1-5-32-578" -Member $env:USERNAME           # grupo "Hyper-V Administrators"
```

El proveedor `virtualbox` sigue disponible en el Vagrantfile para equipos sin el hipervisor de Windows.

**Sin carpetas compartidas** (en Hyper-V requerirían SMB con credenciales): `dac lab capture` sube el script por WinRM (`vagrant upload`) y trae la captura de vuelta en base64, comprobando el sha256, a `tests/datasets/captures/`.

## Capturar un ataque

```bash
dac lab capture T1218.005 --tests 2 --name mshta_vbscript_exec
dac lab capture benign --benign "Get-Process | Out-Null; winget list" --name benign_admin_session
```

`scripts/capture_atomic.ps1` (se ejecuta en la VM con `vagrant winrm --elevated`):

1. Instala los prerrequisitos del test.
2. Marca el inicio, ejecuta el test y espera 20 s a que se escriban los logs.
3. Exporta todos los eventos del intervalo de Sysmon, Security, System, PowerShell y Defender como **JSON plano** (mismo formato que OTRF) y lo comprime con gzip.
   Descarta el logging de PowerShell que genera la propia infraestructura del lab: el proceso de captura, que al cargar Invoke-AtomicRedTeam emite miles de 4103 y 800, y el `wsmprovhost.exe` de la sesión WinRM de Vagrant. Los tests se ejecutan en procesos hijos, así que el PowerShell del ataque se conserva. Hay una excepción: una técnica que use WinRM contra esta misma VM perdería el logging de su `wsmprovhost`.
4. Ejecuta el *cleanup* del test.
5. Escribe `<name>.meta.json` con la técnica, los tests, el número de eventos, la versión de Sysmon y el sha256.

`dac lab capture` registra el dataset en `tests/datasets/sources.yml` con su **sha256**. Si alguien modifica una captura, `dac test` falla.

Después solo queda etiquetarlo en el caso de test de la regla (`detects`, `known_gaps`…) y ejecutar `dac test`. Como **cada regla se ejecuta contra todas las capturas**, cada captura nueva también sirve para medir los falsos positivos del resto de reglas.

## Antivirus del host

Las capturas contienen líneas de comandos de ataques reales. Se guardan con gzip y se evitan los tests más llamativos (volcado de credenciales con herramientas conocidas), pero Defender podría marcar alguna en la máquina de desarrollo. Ver [testing.md](testing.md#datasets-y-antivirus).
