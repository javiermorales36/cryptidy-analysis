# Informe técnico: CVE POTENCIAL EN cryptidy

## Descripción
Uso de `pickle.loads` sin validación permite ejecución remota de código (RCE).

## Archivo afectado
`cryptidy/symmetric_encryption.py`

## Hallazgos
-  Uso de pickle.loads detectado
-  Uso de exec peligroso
- ⚠️ Posible bypass lógico

## Payload generado
`payload_malicioso.bin`

##  Resultado de la ejecución
 Payload ejecutado (puede haber abierto calculadora)

##  Recomendación de parche
Reemplazar `pickle.loads` por `json.loads` si es posible, o validar entrada:
```python
import pickle

def safe_load(data):
    assert isinstance(data, bytes)
    return pickle.loads(data)
```
