<div align="center">

# KRY Core

Biblioteca nativa para criptografia e descriptografia segura de arquivos utilizando AES-256-GCM e Argon2id.

<br>

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Rust](https://img.shields.io/badge/rust-2024-orange)
![License](https://img.shields.io/badge/license-MIT-green)
![Coverage](https://img.shields.io/badge/coverage-80%25+-success)
![AES-256-GCM](https://img.shields.io/badge/AES-256--GCM-red)
![Argon2id](https://img.shields.io/badge/Argon2id-enabled-purple)

<br>

![Build](https://github.com/dioleti/kry-core/actions/workflows/build.yml/badge.svg)
![CI/CD](https://github.com/dioleti/kry-core/actions/workflows/ci-cd.yml/badge.svg)

</div>

A biblioteca foi projetada para ser consumida por aplicações externas através de uma interface C ABI, permitindo
integração com linguagens como:

- C#
- C++
- Delphi
- Python
- Go
- Node.js (via FFI)
- Qualquer linguagem capaz de consumir DLLs nativas

---

## Recursos

- AES-256-GCM
- Argon2id para derivação de chave
- Salt único por arquivo
- Nonce único por arquivo
- Autenticação e integridade embutidas (AEAD)
- Limpeza de memória sensível com Zeroize
- API nativa para interoperabilidade com outras linguagens
- DLL pequena e sem dependência do .NET Runtime

---

## Formato do Arquivo

Arquivos criptografados utilizam a seguinte estrutura:

```text
[KRY1]
[SALT]
[NONCE]
[CIPHERTEXT + TAG]
```

### Cabeçalho

| Campo        | Tamanho  |
|--------------|----------|
| MAGIC_HEADER | 4 bytes  |
| SALT         | 16 bytes |
| NONCE        | 12 bytes |

---

## Criptografia

### Algoritmo

```text
AES-256-GCM
```

### Derivação de Chave

```text
Argon2id
```

Parâmetros atuais:

```text
Memória: 128 MB
Iterações: 3
Paralelismo: 1
Tamanho da chave: 32 bytes
```

---

## API Exportada

### Obter versão

```c
const char* version(void);
```

Retorno:

```text
1.0.0
```

---

### Criptografar arquivo

```c
int encrypt(
    const char* path,
    const char* password
);
```

---

### Descriptografar arquivo

```c
int decrypt(
    const char* path,
    const char* password
);
```

---

## Códigos de Retorno

| Código | Significado            |
|--------|------------------------|
| 0      | Sucesso                |
| -1     | Caminho nulo           |
| -2     | Senha nula             |
| -3     | Caminho UTF-8 inválido |
| -4     | Senha UTF-8 inválida   |
| -5     | Falha na operação      |

---

## Exemplo em C#

```csharp
using System;
using System.Runtime.InteropServices;

internal static class KryNative
{
    [DllImport("kry_core.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr version();

    [DllImport("kry_core.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int encrypt(
        string path,
        string password
    );

    [DllImport("kry_core.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int decrypt(
        string path,
        string password
    );
}
```

Obtendo a versão:

```csharp
string version =
    Marshal.PtrToStringAnsi(
        KryNative.version()
    )!;

Console.WriteLine(version);
```

Criptografando:

```csharp
int result = KryNative.encrypt(
    @"C:\arquivo.txt",
    "MinhaSenha"
);

if (result == 0)
{
    Console.WriteLine("Arquivo criptografado.");
}
```

---

## Build

Compilação Release:

```bash
cargo build --release
```

Windows:

```text
target/release/kry_core.dll
```

Linux:

```text
target/release/libkry_core.so
```

macOS:

```text
target/release/libkry_core.dylib
```

---

## Segurança

A biblioteca utiliza:

- AES-256-GCM
- Argon2id
- Salt aleatório por arquivo
- Nonce aleatório por arquivo
- Limpeza de memória sensível via Zeroize

A biblioteca não transmite dados pela rede e opera exclusivamente sobre o sistema de arquivos local.

---

## Licença

Este projeto é distribuído sob a licença MIT.

---

Copyright © 2026 - Dioleti® - Fabricio Paulo

Todos os direitos reservados.