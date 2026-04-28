import { useEffect, useRef, useState } from 'react';
import { motion } from 'framer-motion';

// One full session: scan → report → harden offer → watch enable.
// Commands/paths/IPs stay untranslated, prose has { en, ru }.
const session = [
  { t: 'cmd', text: '$ sudo yagura' },
  {
    t: 'log',
    en: '→ YAGURA v0.1.0 — security audit for Linux servers',
    ru: '→ YAGURA v0.1.0 — аудит безопасности Linux-серверов',
  },
  {
    t: 'log',
    en: '→ Hostname: prod-web-01 · Ubuntu 22.04 LTS · kernel 5.15.0-91',
    ru: '→ Хост: prod-web-01 · Ubuntu 22.04 LTS · ядро 5.15.0-91',
  },
  { t: 'pause', ms: 800 },

  { t: 'log', en: '→ Collecting system info...', ru: '→ Собираю системную информацию...' },
  { t: 'ok', en: '✓ Network: 12 listeners, 3 established', ru: '✓ Сеть: 12 listener, 3 established' },
  { t: 'ok', en: '✓ SSH config parsed', ru: '✓ SSH-конфиг прочитан' },
  { t: 'ok', en: '✓ Firewall: ufw active, 4 rules', ru: '✓ Firewall: ufw активен, 4 правила' },
  { t: 'ok', en: '✓ Users: 3 users, 1 with sudo', ru: '✓ Юзеры: 3 пользователя, 1 с sudo' },
  { t: 'ok', en: '✓ Services: 87 enabled', ru: '✓ Сервисы: 87 enabled' },
  { t: 'ok', en: '✓ Packages: 1247 installed, 23 updates available', ru: '✓ Пакеты: 1247 установлено, 23 обновления' },
  { t: 'ok', en: '✓ Cron jobs: 5 system, 2 user', ru: '✓ Cron: 5 системных, 2 пользовательских' },
  { t: 'ok', en: '✓ Kernel params + critical file hashes', ru: '✓ Параметры ядра + хеши критичных файлов' },
  { t: 'pause', ms: 1200 },

  { t: 'log', en: '┌─ SECURITY SCORE: 64/100 (NEEDS WORK) ─┐', ru: '┌─ SECURITY SCORE: 64/100 (NEEDS WORK) ─┐' },
  { t: 'log', en: '│ SSH:        █████░░░░░  50/100        │', ru: '│ SSH:        █████░░░░░  50/100        │' },
  { t: 'log', en: '│ Firewall:   ████████░░  80/100        │', ru: '│ Firewall:   ████████░░  80/100        │' },
  { t: 'log', en: '│ Updates:    ██████░░░░  60/100        │', ru: '│ Updates:    ██████░░░░  60/100        │' },
  { t: 'log', en: '│ Hardening:  █████░░░░░  55/100        │', ru: '│ Hardening:  █████░░░░░  55/100        │' },
  { t: 'log', en: '└────────────────────────────────────────┘', ru: '└────────────────────────────────────────┘' },
  { t: 'pause', ms: 1000 },

  {
    t: 'evt',
    en: '⛔ SSH-001  PermitRootLogin yes — root can SSH in',
    ru: '⛔ SSH-001  PermitRootLogin yes — root может зайти по SSH',
  },
  {
    t: 'evt',
    en: '⛔ FW-002   iptables INPUT default ACCEPT — no default block',
    ru: '⛔ FW-002   iptables INPUT default ACCEPT — нет дефолтного блока',
  },
  {
    t: 'evt',
    en: '⛔ KER-002  ASLR off — kernel.randomize_va_space = 0',
    ru: '⛔ KER-002  ASLR выключен — kernel.randomize_va_space = 0',
  },
  { t: 'pause', ms: 1400 },

  {
    t: 'log',
    en: '→ AI analysis (Claude): top risk is root SSH login',
    ru: '→ AI-разбор (Claude): главный риск — root-логин по SSH',
  },
  {
    t: 'log',
    en: '→ Brute-forcers try this first. Disable now.',
    ru: '→ Брутфорсеры пробуют это первым. Выключи сейчас.',
  },
  { t: 'pause', ms: 1400 },

  { t: 'cmd', text: '? Apply recommended hardening?  [Yes]' },
  { t: 'ok', en: '✓ SSH-001 PermitRootLogin → no', ru: '✓ SSH-001 PermitRootLogin → no' },
  { t: 'ok', en: '✓ FW-002  iptables INPUT → DROP (default policy)', ru: '✓ FW-002  iptables INPUT → DROP (default policy)' },
  { t: 'ok', en: '✓ KER-001 syncookies + ASLR enabled', ru: '✓ KER-001 syncookies + ASLR включены' },
  { t: 'ok', en: '✓ rollback commands saved to /etc/yagura/config.yml', ru: '✓ откат сохранён в /etc/yagura/config.yml' },
  { t: 'pause', ms: 1200 },

  { t: 'cmd', text: '? Enable yagura-watch (Telegram alerts)?  [Yes]' },
  { t: 'log', en: '→ Telegram bot validated · test message sent', ru: '→ Telegram-бот проверен · тестовое сообщение отправлено' },
  { t: 'ok', en: '✓ baseline saved: 12 listeners, 87 units, 5 crons', ru: '✓ baseline сохранён: 12 listener, 87 юнитов, 5 cron' },
  { t: 'ok', en: '✓ yagura-watch.service enabled (interval: 5 min)', ru: '✓ yagura-watch.service включён (интервал: 5 мин)' },
  { t: 'pause', ms: 1800 },

  {
    t: 'evt',
    en: '⚠ 14:23:11  W-NET-001  new listener :4444/tcp',
    ru: '⚠ 14:23:11  W-NET-001  новый listener :4444/tcp',
  },
  {
    t: 'log',
    en: '→ Process: /tmp/.x/miner (PID 13371) · user: root',
    ru: '→ Процесс: /tmp/.x/miner (PID 13371) · юзер: root',
  },
  { t: 'tg', en: '📩 Telegram alert sent (HIGH)', ru: '📩 Алерт отправлен в Telegram (HIGH)' },
  { t: 'pause', ms: 1200 },

  {
    t: 'evt',
    en: '⚠ 14:23:14  W-PROC-003  reverse-shell heuristic',
    ru: '⚠ 14:23:14  W-PROC-003  эвристика reverse-shell',
  },
  {
    t: 'log',
    en: '→ bash → ESTABLISHED 185.220.101.42:9001 (external)',
    ru: '→ bash → ESTABLISHED 185.220.101.42:9001 (внешний)',
  },
  { t: 'tg', en: '📩 Telegram alert sent (CRITICAL)', ru: '📩 Алерт отправлен в Telegram (CRITICAL)' },
  { t: 'pause', ms: 1500 },

  {
    t: 'evt',
    en: '⚠ 14:24:02  W-FILE-001  /etc/passwd hash changed',
    ru: '⚠ 14:24:02  W-FILE-001  хеш /etc/passwd изменился',
  },
  {
    t: 'log',
    en: '→ Diff: +backdoor:x:0:0::/root:/bin/bash (UID 0!)',
    ru: '→ Diff: +backdoor:x:0:0::/root:/bin/bash (UID 0!)',
  },
  { t: 'tg', en: '📩 Telegram alert sent (CRITICAL)', ru: '📩 Алерт отправлен в Telegram (CRITICAL)' },
  { t: 'pause', ms: 1600 },

  { t: 'cmd', text: '$ yagura watch status' },
  { t: 'log', en: '→ Service:    active (running)', ru: '→ Сервис:    active (running)' },
  { t: 'log', en: '→ Last check: 4s ago', ru: '→ Последняя проверка: 4 сек назад' },
  { t: 'log', en: '→ Alerts 24h: 7 (CRITICAL: 2, HIGH: 4, MEDIUM: 1)', ru: '→ Алертов за 24ч: 7 (CRITICAL: 2, HIGH: 4, MEDIUM: 1)' },
  { t: 'log', en: '→ CPU usage:  ~0.1%  ·  RAM: 22 MB', ru: '→ CPU:  ~0.1%  ·  RAM: 22 MB' },
  { t: 'ok', en: '✓ Tower stands. Watching.', ru: '✓ Башня стоит. Наблюдаю.' },
];

const TYPE_DELAY_FIRST = 600;
const TYPE_DELAY = 1000;
const MAX_LINES = 14;

const lineClass = (t) =>
  t === 'cmd'
    ? 'text-zinc-100'
    : t === 'ok'
    ? 'text-sky-400'
    : t === 'evt'
    ? 'text-amber-400'
    : t === 'tg'
    ? 'text-emerald-400'
    : 'text-zinc-500';

const resolveText = (step, lang) => step.text ?? step[lang] ?? step.en;

export default function TerminalDemo() {
  const [lang, setLang] = useState('ru');
  const [history, setHistory] = useState([]);
  const [idx, setIdx] = useState(0);
  const keyRef = useRef(0);
  const scrollRef = useRef(null);

  useEffect(() => {
    if (idx >= session.length) return;

    const step = session[idx];

    if (step.t === 'pause') {
      const id = setTimeout(() => setIdx((i) => i + 1), step.ms);
      return () => clearTimeout(id);
    }

    const delay = idx === 0 ? TYPE_DELAY_FIRST : TYPE_DELAY;
    const id = setTimeout(() => {
      setHistory((h) => {
        const next = [...h, { step, key: keyRef.current++ }];
        return next.length > MAX_LINES ? next.slice(next.length - MAX_LINES) : next;
      });
      setIdx((i) => i + 1);
    }, delay);
    return () => clearTimeout(id);
  }, [idx]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [history]);

  return (
    <div className="rounded-2xl bg-zinc-900/80 border border-zinc-800 overflow-hidden shadow-2xl shadow-sky-500/5 backdrop-blur">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-zinc-800 bg-zinc-900/60">
        <div className="w-3 h-3 rounded-full bg-zinc-700" />
        <div className="w-3 h-3 rounded-full bg-zinc-700" />
        <div className="w-3 h-3 rounded-full bg-zinc-700" />
        <span className="ml-3 text-xs text-zinc-500 font-mono">root@prod-web-01 ~</span>
        <div className="ml-auto flex items-center gap-1 text-[10px] font-mono">
          <button
            type="button"
            onClick={() => setLang('ru')}
            className={`px-2 py-0.5 rounded transition-colors ${
              lang === 'ru'
                ? 'bg-zinc-800 text-zinc-100'
                : 'text-zinc-500 hover:text-zinc-300'
            }`}
            aria-pressed={lang === 'ru'}
          >
            RU
          </button>
          <button
            type="button"
            onClick={() => setLang('en')}
            className={`px-2 py-0.5 rounded transition-colors ${
              lang === 'en'
                ? 'bg-zinc-800 text-zinc-100'
                : 'text-zinc-500 hover:text-zinc-300'
            }`}
            aria-pressed={lang === 'en'}
          >
            EN
          </button>
        </div>
      </div>

      <div
        ref={scrollRef}
        className="p-5 font-mono text-xs md:text-sm leading-relaxed h-[320px] overflow-hidden"
      >
        {history.map(({ step, key }) => (
          <motion.div
            key={key}
            initial={{ opacity: 0, x: -8 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.55, ease: 'easeOut' }}
            className={lineClass(step.t)}
          >
            {resolveText(step, lang)}
          </motion.div>
        ))}
        <span className="inline-block w-2 h-4 bg-sky-400 animate-pulse ml-0.5 align-middle" />
      </div>
    </div>
  );
}
