🛡️ SentinelAuth: Roadmap de Implementação AppSec

Este documento detalha o progresso do ecossistema de segurança e as próximas defesas a serem erguidas.

🟢 FASE 1: O Alicerce (Concluído)

Foco: Autenticação Robusta e Gestão de Identidade.

[x] Criptografia de Senhas: Implementação do Argon2id (OWASP Standard).

[x] Identidade Segura: Uso de UUIDs (Prevenção de Enumeração).

[x] JWT Core: Emissão e validação estrita via Regex.

[x] Refresh Token com Rotação: Proteção contra roubo de sessão.

[x] Validação de Inputs: Políticas de senhas fortes no DTO.

🟢 FASE 2: Perímetro e Observabilidade (Concluído)

Foco: Detecção de anomalias e segurança de transporte.

[x] Rate Limiting (Bucket4j): Proteção contra Brute Force (5 req/min por IP).

[x] Global Exception Handler: Escudo contra vazamento de stacktraces.

[x] Automation Scripts: Postman local storage para tokens JWT e MFA.

[x] Security Headers: (Pronto para configuração em SecurityConfig).

🟡 FASE 3: Autenticação Multi-Fatorial (Em Andamento)

Foco: Proteção contra comprometimento de credenciais via Out-of-Band (OOB).

[x] MFA via Email OTP: Substituição do TOTP legível por códigos dinâmicos via Email.

[x] Fluxo de Login em Dois Passos: Implementação de tokens temporários (PENDING) e endpoint /verify.

[x] Limpeza de Legado: Remoção de bibliotecas e DTOs de TOTP/Base32.

[ ] SMTP Real Integration: Transição do log do console para um servidor de email (Gmail/SendGrid).

🔴 FASE 4: Endurecimento (Hardening) e DevOps

Foco: Estabilidade em escala e conformidade.

[ ] Distributed Rate Limiting: Migração do Map em memória para Redis.

[ ] Audit Trail Avançado: Registro detalhado de eventos de MFA em tabela de auditoria.

[ ] RBAC Avançado: Controle de acesso baseado em roles (ADMIN, USER).



🔴 FASE 5: Expansão de Integrações e Produção

Foco: Conectar o SentinelAuth ao mundo real e escalabilidade.

[ ] Rate Limiting Distribuído: Migração do controle de memória local do Bucket4j para uma instância isolada do Redis.

[ ] CORS e Integração Frontend (React): Configurações de cabeçalhos CORS e persistência de Refresh Tokens usando Cookies seguros com as flags HttpOnly, Secure e SameSite=Strict.

[ ] Integração OAuth2: Suporte opcional para Social Login (ex: Fazer login com o Google/GitHub) mantendo as mesmas políticas rígidas de sessão.