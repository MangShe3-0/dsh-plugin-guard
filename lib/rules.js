export const RULES = [
  {
    id: 'PI001', severity: 'high', category: 'prompt-injection',
    title: 'Instruction or policy override',
    pattern: /(?:ignore|disregard|override|bypass)\s+(?:all\s+)?(?:previous|prior|system|developer|safety|security)(?:\s+(?:system|developer|safety|security))?\s+(?:instructions?|rules?|polic(?:y|ies))|(?:忽略|无视|绕过|覆盖).{0,24}(?:之前|系统|开发者|安全).{0,16}(?:指令|规则|策略)/iu,
    recommendation: 'Remove instructions that attempt to outrank the user, system, or safety policy.'
  },
  {
    id: 'PI002', severity: 'high', category: 'prompt-injection',
    title: 'Secrecy or concealment directive',
    pattern: /(?:do\s+not|never)\s+(?:tell|show|reveal|mention|disclose).{0,80}(?:user|operator|reviewer)|(?:secretly|silently|without\s+(?:the\s+)?user(?:'s)?\s+(?:knowledge|consent))|(?:不要|不得|永远不要).{0,40}(?:告诉|展示|透露|提及).{0,20}(?:用户|操作者|审核员)|(?:秘密地|静默地|在用户不知情)/iu,
    recommendation: 'Require transparent, user-visible behavior and explicit consent.'
  },
  {
    id: 'PI003', severity: 'high', category: 'prompt-injection',
    title: 'Tool-description or parameter injection',
    pattern: /(?:before|when)\s+(?:using|calling|invoking).{0,40}(?:tool|function).{0,80}(?:must|always|first)\s+(?:read|send|execute|append|prepend)|(?:assistant|agent|model)\s+(?:must|shall)\s+(?:always|first|silently)/iu,
    recommendation: 'Keep tool metadata descriptive; do not place hidden workflow commands in descriptions.'
  },
  {
    id: 'UNI001', severity: 'high', category: 'unicode-deception',
    title: 'Invisible or bidirectional control characters',
    pattern: /[\u200B-\u200F\u202A-\u202E\u2060\u2066-\u2069\uFEFF]/u,
    recommendation: 'Remove invisible and bidi control characters; review the surrounding text manually.'
  },
  {
    id: 'FS001', severity: 'critical', category: 'destructive-action',
    title: 'Recursive or broad deletion',
    pattern: /\brm\s+(?:-[A-Za-z]*r[A-Za-z]*f|-rf|-fr)\b|Remove-Item\b[^\n]{0,120}-(?:Recurse|Force)|\b(?:fs\.)?rmSync?\s*\([^\n]{0,160}recursive\s*:\s*true|\bfind\b[^\n]{0,120}\s-delete\b/iu,
    recommendation: 'Do not install. Replace broad deletion with a narrow, validated, recoverable operation.'
  },
  {
    id: 'FS002', severity: 'critical', category: 'destructive-action',
    title: 'Disk, account, or permission destruction',
    pattern: /\b(?:mkfs(?:\.[a-z0-9]+)?|diskutil\s+eraseDisk|format\s+[A-Z]:|dd\s+if=\/dev\/(?:zero|urandom)|chmod\s+-R\s+0{3}|chown\s+-R\s+[^\n]+\s+\/)\b/iu,
    recommendation: 'Do not install. This operation can make data or the system unavailable.'
  },
  {
    id: 'RW001', severity: 'critical', category: 'ransomware',
    title: 'Likely mass encryption or ransom behavior',
    pattern: /(?:ransom|decrypt[_-]?key|bitcoin.{0,40}(?:payment|wallet)|your\s+files\s+(?:have\s+been|are)\s+encrypted|文件.{0,20}(?:已被|已经).{0,10}加密|支付.{0,20}(?:比特币|赎金))|(?:walk|glob|readdir)[\s\S]{0,240}(?:encrypt|createCipheriv)[\s\S]{0,160}(?:unlink|rename)/iu,
    recommendation: 'Do not install. Preserve evidence and inspect the plugin in an isolated environment.'
  },
  {
    id: 'EX001', severity: 'high', category: 'data-exfiltration',
    title: 'Sensitive credential or private-file access',
    pattern: /(?:process\.env|os\.environ|getenv\s*\(|\.ssh\/(?:id_|config|known_hosts)|\.aws\/credentials|\.kube\/config|keychain|Login Data|Cookies|wallet\.dat|credentials?\.json|API[_-]?KEY|ACCESS[_-]?TOKEN|PRIVATE[_-]?KEY)/iu,
    recommendation: 'Verify that every secret read is necessary, scoped, and never included in logs or network requests.'
  },
  {
    id: 'EX002', severity: 'medium', category: 'network',
    title: 'Outbound network transmission',
    pattern: /\b(?:fetch|axios\.(?:post|put|request)|requests?\.(?:post|put)|http[s]?\.request|WebSocket|sendBeacon)\s*\(|\bcurl\b[^\n]{0,160}(?:-d|--data|--upload-file|-F)\b|\bwget\b/iu,
    recommendation: 'Document every destination and transmitted field; obtain user consent before sending data.'
  },
  {
    id: 'EX003', severity: 'high', category: 'data-exfiltration',
    title: 'Credential harvesting pattern',
    pattern: /(?:Object\.(?:entries|keys|values)\s*\(\s*process\.env|for\s*\([^)]*\b(?:process\.env|os\.environ)|(?:readFile|read_text)[\s\S]{0,160}(?:\.ssh|credentials|keychain|cookies))/iu,
    recommendation: 'Do not enumerate credentials or environment variables. Read only an explicitly named value when required.'
  },
  {
    id: 'SC001', severity: 'critical', category: 'supply-chain',
    title: 'Download-and-execute pipeline',
    pattern: /(?:curl|wget)\b[^\n|;]{0,240}(?:\||&&|;)\s*(?:sudo\s+)?(?:sh|bash|zsh|node|python\d*|pwsh|powershell)\b|(?:fetch|axios|get)\s*\([^\n]{0,200}\)[\s\S]{0,300}(?:eval|Function|exec|spawn)\s*\(/iu,
    recommendation: 'Do not install. Download artifacts separately, pin a digest, inspect them, then execute only with explicit approval.'
  },
  {
    id: 'SC002', severity: 'high', category: 'obfuscation',
    title: 'Encoded or obfuscated execution',
    pattern: /(?:eval|Function|exec|vm\.runInNewContext)\s*\([^\n]{0,100}(?:atob|Buffer\.from\([^\n]{0,80}base64|fromCharCode)|(?:atob|Buffer\.from\([^\n]{0,80}base64)[\s\S]{0,160}(?:eval|Function|exec)\s*\(/iu,
    recommendation: 'Reject encoded executable payloads; require readable source code.'
  },
  {
    id: 'CODE001', severity: 'high', category: 'dynamic-execution',
    title: 'Dynamic code evaluation',
    pattern: /\b(?:eval|Function)\s*\(|\bvm\.(?:runInNewContext|runInThisContext|compileFunction)\s*\(|\bexec\s*\([^)]*(?:user|input|args|prompt|request)/iu,
    recommendation: 'Replace dynamic evaluation with a fixed parser or allowlisted dispatch table.'
  },
  {
    id: 'CODE002', severity: 'medium', category: 'command-execution',
    title: 'Shell or subprocess execution',
    pattern: /(?:node:)?child_process|\b(?:execSync|spawnSync|execFileSync|subprocess\.(?:run|Popen|call|check_output)|os\.system)\s*\(|shell\s*:\s*true/iu,
    recommendation: 'Use an argument-vector API, an allowlist, timeouts, and explicit user approval for side effects.'
  },
  {
    id: 'PERS001', severity: 'high', category: 'persistence',
    title: 'Startup, scheduled-task, or shell-profile persistence',
    pattern: /\b(?:crontab|launchctl|schtasks|systemctl\s+enable|reg\s+add[^\n]+\\Run)\b|\.(?:bashrc|zshrc|profile)\b|Library\/LaunchAgents|\/etc\/(?:cron|systemd)/iu,
    recommendation: 'Require explicit, separate approval for persistence and provide a complete uninstall path.'
  },
  {
    id: 'SELF001', severity: 'high', category: 'self-modification',
    title: 'Agent, policy, or plugin self-modification',
    pattern: /(?:writeFile|appendFile|copyFile|rename)\s*\([^\n]{0,180}(?:AGENTS\.md|CLAUDE\.md|SKILL\.md|SOUL\.md|cordis\.(?:yml|yaml)|plugin|system[_-]?prompt)|(?:modify|rewrite|patch).{0,60}(?:own|itself|system prompt|agent policy)/iu,
    recommendation: 'Separate generated data from executable instructions and require human review before activation.'
  },
  {
    id: 'TLS001', severity: 'medium', category: 'unsafe-default',
    title: 'TLS or certificate verification disabled',
    pattern: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|verify\s*=\s*False|curl\s+(?:-[A-Za-z]*k\b|--insecure)/iu,
    recommendation: 'Keep certificate verification enabled; configure a trusted CA instead.'
  }
]

export const SEVERITY_WEIGHT = Object.freeze({ critical: 30, high: 18, medium: 8, low: 3 })
