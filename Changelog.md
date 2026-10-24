# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-26

### Adicionado

- Lançamento inicial do Kry Core.
- Implementação de criptografia autenticada utilizando AES-256-GCM.
- Implementação de descriptografia autenticada utilizando AES-256-GCM.
- Derivação segura de chaves baseada em senha com Argon2id.
- Geração automática de salt aleatório exclusivo por arquivo.
- Geração automática de nonce aleatório exclusivo por arquivo.
- Verificação de integridade e autenticidade através de AEAD (Authenticated Encryption with Associated Data).
- Formato proprietário de arquivo baseado em cabeçalho de identificação KRY1.
- Suporte a criptografia baseada em senha.
- Remoção automática do arquivo original após criptografia bem-sucedida.
- Remoção automática do arquivo criptografado após descriptografia bem-sucedida.
- Restauração automática do nome original do arquivo durante a descriptografia.
- Exportação da biblioteca como DLL nativa compatível com C ABI.
- API pública para integração com aplicações externas.
- Função nativa `version` para consulta da versão da biblioteca.
- Função nativa `encrypt` para criptografia de arquivos.
- Função nativa `decrypt` para descriptografia de arquivos.
- Validação de ponteiros nulos recebidos pela interface FFI.
- Validação de parâmetros UTF-8 recebidos pela interface FFI.
- Códigos padronizados de retorno para integração com aplicações externas.
- Limpeza segura de dados sensíveis em memória utilizando Zeroize.
- Limpeza segura de chaves derivadas após utilização.
- Limpeza segura de conteúdo descriptografado após persistência em disco.
- Detecção de arquivos adulterados ou corrompidos durante a descriptografia.
- Compatibilidade multiplataforma para Windows, Linux e macOS.
- Pipeline automatizado de Integração Contínua (CI) via GitHub Actions.
- Verificação automática de compilação em múltiplos sistemas operacionais.
- Execução automática de testes unitários.
- Verificação automática de conformidade de formatação com `cargo fmt`.
- Verificação automática de qualidade de código com `cargo clippy`.
- Auditoria automática de vulnerabilidades em dependências com `cargo audit`.
- Auditoria automática de dependências e licenças com `cargo deny`.
- Validação automática de cobertura mínima de testes.
- Licenciamento do projeto sob a licença MIT.
- Adicionado guard-rail para impedir criptografia recursiva sobre arquivo já criptografado;
- Adicionado guard-rail para evitar tentativa de descriptografia de arquivo não criptografado.