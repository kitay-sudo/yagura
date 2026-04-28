import { motion, AnimatePresence } from 'framer-motion';
import {
  Terminal,
  Bell,
  Brain,
  FileWarning,
  Lock,
  Github,
  Gauge,
  Network,
  Copy,
  Check,
  ArrowUp,
  Heart,
  Send,
  Shield,
  Eye,
  ScanSearch,
  Activity,
  AlertTriangle,
  Fingerprint,
  Radar,
} from 'lucide-react';
import { useState, useEffect } from 'react';
import GridBackground from '../components/landing/GridBackground';
import Reveal from '../components/landing/Reveal';
import TerminalDemo from '../components/landing/TerminalDemo';
import FeatureCard from '../components/landing/FeatureCard';
import FAQItem from '../components/landing/FAQItem';
import YaguraMark from '../components/landing/YaguraMark';
import KanjiWatermark from '../components/landing/KanjiWatermark';
import JapaneseDivider from '../components/landing/JapaneseDivider';

const REPO_URL = 'https://gitlab.com/kitay-sudo/yagura';
const INSTALL_CMD = 'curl -sSL https://gitlab.com/kitay-sudo/yagura/-/raw/main/install.sh | sudo bash';

export default function Landing() {
  return (
    <div className="min-h-dvh bg-zinc-950 text-zinc-100 antialiased">
      <Nav />
      <Hero />
      <YaguraStory />
      <LogosStrip />
      <TwoModes />
      <Features />
      <BehavioralRules />
      <Versus />
      <HowItWorks />
      <DemoSection />
      <FAQ />
      <Support />
      <CTA />
      <Footer />
      <BackToTop />
    </div>
  );
}

function BackToTop() {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const onScroll = () => setVisible(window.scrollY > 400);
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  const scrollUp = () =>
    window.scrollTo({ top: 0, behavior: 'smooth' });

  return (
    <AnimatePresence>
      {visible && (
        <motion.button
          key="back-to-top"
          type="button"
          onClick={scrollUp}
          aria-label="Наверх"
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: 12 }}
          transition={{ duration: 0.2, ease: 'easeOut' }}
          className="fixed z-50 bottom-6 right-6 inline-flex items-center justify-center w-11 h-11 rounded-full border border-sky-500/30 bg-zinc-900/80 backdrop-blur text-sky-400 hover:text-sky-300 hover:border-sky-500/60 hover:bg-zinc-900 shadow-lg shadow-sky-500/10 transition-colors"
        >
          <ArrowUp size={18} strokeWidth={2.2} />
        </motion.button>
      )}
    </AnimatePresence>
  );
}

function Nav() {
  return (
    <header className="sticky top-0 z-50 border-b border-zinc-900/80 bg-zinc-950/70 backdrop-blur-lg">
      <div className="max-w-6xl mx-auto px-5 h-14 flex items-center justify-between">
        <a href="#top" className="flex items-center gap-2.5 font-semibold">
          <span className="inline-flex items-center justify-center w-8 h-8 rounded-md border border-sky-500/30 bg-sky-500/10 text-sky-400">
            <YaguraMark size={22} />
          </span>
          <span className="tracking-tight">YAGURA</span>
        </a>

        <nav className="hidden md:flex items-center gap-7 text-sm text-zinc-400">
          <a href="#way" className="hover:text-zinc-100 transition-colors">Башня</a>
          <a href="#modes" className="hover:text-zinc-100 transition-colors">Режимы</a>
          <a href="#features" className="hover:text-zinc-100 transition-colors">Возможности</a>
          <a href="#how" className="hover:text-zinc-100 transition-colors">Как работает</a>
          <a href="#install" className="hover:text-zinc-100 transition-colors">Установка</a>
          <a href="#faq" className="hover:text-zinc-100 transition-colors">FAQ</a>
        </nav>

        <a
          href={REPO_URL}
          target="_blank"
          rel="noreferrer"
          className="text-sm font-medium bg-sky-500 hover:bg-sky-400 text-zinc-950 rounded-lg px-3.5 py-1.5 transition-colors flex items-center gap-1.5"
        >
          <Github size={14} />
          GitLab
        </a>
      </div>
    </header>
  );
}

function Hero() {
  return (
    <section id="top" className="relative overflow-hidden">
      <GridBackground />

      <KanjiWatermark
        char="櫓"
        className="right-[3%] top-[12%] text-[180px] md:text-[260px] hidden sm:block"
        target={0.045}
      />
      <KanjiWatermark
        char="見"
        className="right-[3%] top-[40%] text-[180px] md:text-[260px] hidden sm:block"
        target={0.045}
      />
      <KanjiWatermark
        char="番"
        className="left-[4%] top-[20%] text-[160px] md:text-[220px] hidden md:block"
        target={0.03}
      />

      <div className="relative max-w-6xl mx-auto px-5 pt-20 md:pt-28 pb-20 md:pb-32">
        <Reveal>
          <div className="flex justify-center">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-zinc-800 bg-zinc-900/60 text-xs text-zinc-400">
              <span className="w-1.5 h-1.5 rounded-full bg-sky-400 animate-pulse" />
              <span className="font-serif-jp text-zinc-500">櫓</span>
              <span className="h-3 w-px bg-zinc-700" />
              Аудит безопасности + поведенческий watchdog · MIT
            </div>
          </div>
        </Reveal>

        <Reveal delay={0.05}>
          <h1 className="mt-6 text-center text-4xl md:text-6xl font-semibold tracking-tight leading-[1.05]">
            Сторожевая башня.<br />
            <span className="bg-gradient-to-r from-sky-400 to-cyan-300 bg-clip-text text-transparent">
              Видит всё. Молчит до угрозы.
            </span>
          </h1>
        </Reveal>

        <Reveal delay={0.08}>
          <p className="mt-6 text-center text-lg md:text-xl text-zinc-200 max-w-2xl mx-auto leading-relaxed font-medium">
            Аудит безопасности Linux-сервера за 60 секунд + опциональный watchdog
            с поведенческими алертами в Telegram. Без баз сигнатур.
          </p>
        </Reveal>

        <Reveal delay={0.16}>
          <p className="mt-5 text-center text-sm md:text-base text-zinc-400 max-w-2xl mx-auto leading-relaxed">
            Один Python-скрипт. AI-разбор отчёта на выбор (Claude / GPT / Gemini).
            Парный проект к <a href="https://github.com/kitay-sudo/goronin" target="_blank" rel="noreferrer" className="text-sky-400 hover:text-sky-300">GORONIN</a> —
            тот ловит и бьёт, этот смотрит и предупреждает.
          </p>
        </Reveal>

        <Reveal delay={0.15}>
          <div className="mt-8 max-w-2xl mx-auto">
            <InstallCommand />
          </div>
        </Reveal>

        <Reveal delay={0.2}>
          <div className="mt-5 flex flex-col sm:flex-row items-center justify-center gap-3">
            <a
              href={REPO_URL}
              target="_blank"
              rel="noreferrer"
              className="w-full sm:w-auto flex items-center justify-center gap-2 text-zinc-300 hover:text-zinc-100 border border-zinc-800 hover:border-zinc-700 rounded-xl px-5 py-3 transition-colors"
            >
              <Github size={16} />
              Исходники на GitLab
            </a>
            <a
              href="#how"
              className="w-full sm:w-auto flex items-center justify-center gap-2 text-zinc-400 hover:text-zinc-200 transition-colors px-5 py-3"
            >
              <Terminal size={16} />
              Как работает
            </a>
          </div>
        </Reveal>

        <Reveal delay={0.25}>
          <div className="mt-6 text-center text-xs text-zinc-500">
            Бесплатно навсегда · Полный код открыт · MIT-лицензия · Ubuntu / Debian / CentOS / Rocky / Arch
          </div>
        </Reveal>

        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.3, ease: [0.22, 1, 0.36, 1] }}
          className="mt-14 md:mt-20 max-w-3xl mx-auto"
        >
          <TerminalDemo />
        </motion.div>
      </div>
    </section>
  );
}

function InstallCommand() {
  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(INSTALL_CMD);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* empty */
    }
  };

  return (
    <div className="rounded-2xl border border-sky-500/30 bg-zinc-900/80 backdrop-blur p-4 shadow-lg shadow-sky-500/10">
      <div className="flex items-center justify-between gap-3">
        <code className="text-xs sm:text-sm text-sky-300 font-mono break-all flex-1 min-w-0">
          {INSTALL_CMD}
        </code>
        <button
          onClick={onCopy}
          className="shrink-0 inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1.5 rounded-md border border-zinc-700 hover:border-sky-500/50 hover:bg-sky-500/10 transition-colors text-zinc-300"
          aria-label="Скопировать команду"
        >
          {copied ? <Check size={14} className="text-sky-400" /> : <Copy size={14} />}
          {copied ? 'Скопировано' : 'Копировать'}
        </button>
      </div>
    </div>
  );
}

function YaguraStory() {
  return (
    <section id="way" className="relative border-y border-zinc-900/80 overflow-hidden">
      <KanjiWatermark
        char="櫓"
        className="left-[50%] top-[50%] -translate-x-1/2 -translate-y-1/2 text-[280px] md:text-[440px]"
        target={0.035}
      />

      <div className="relative max-w-4xl mx-auto px-5 py-20 md:py-28 text-center">
        <Reveal>
          <JapaneseDivider kanji="櫓" label="The Tower" />
          <h2 className="text-3xl md:text-5xl font-semibold tracking-tight leading-tight">
            Почему <span className="text-sky-400">башня</span>?
          </h2>
        </Reveal>

        <Reveal delay={0.1}>
          <p className="mt-6 text-zinc-400 leading-relaxed md:text-lg">
            Yagura — 櫓 — сторожевая башня на стене самурайского замка. Не для атаки — для наблюдения.
            Стоит, видит, предупреждает.
          </p>
        </Reveal>

        <Reveal delay={0.15}>
          <p className="mt-4 text-zinc-400 leading-relaxed md:text-lg">
            Ронин (浪人) ходит, ловит, отвечает ударом — это <a href="https://github.com/kitay-sudo/goronin" target="_blank" rel="noreferrer" className="text-sky-400 hover:text-sky-300 font-mono">GORONIN</a>.
            Yagura — про второе. Один раз провёл аудит — увидел картину. Включил watch — получил сторожа.
            Не охотник. Наблюдатель.
          </p>
        </Reveal>

        <Reveal delay={0.2}>
          <div className="mt-10 grid grid-cols-1 md:grid-cols-3 gap-4">
            {[
              { kanji: '見', label: 'Зрение', desc: 'Поведение, а не сигнатуры. Ловит то, чего нет ни в одной базе.' },
              { kanji: '静', label: 'Тишина', desc: 'Не ставит eBPF, не качает фиды. ~0.1% CPU, 22 МБ RAM в watch-режиме.' },
              { kanji: '番', label: 'Стража', desc: 'Алерты в Telegram идут только наружу. Бот не принимает команды — не вектор атаки.' },
            ].map((v) => (
              <div
                key={v.kanji}
                className="rounded-2xl border border-zinc-800/80 bg-zinc-900/40 p-5 text-left"
              >
                <div className="flex items-center gap-3 mb-2">
                  <span
                    className="text-2xl text-zinc-600"
                    style={{ fontFamily: '"Noto Serif JP", serif', fontWeight: 500 }}
                  >
                    {v.kanji}
                  </span>
                  <span className="text-sm font-semibold text-zinc-100">{v.label}</span>
                </div>
                <p className="text-sm text-zinc-400 leading-relaxed">{v.desc}</p>
              </div>
            ))}
          </div>
        </Reveal>
      </div>
    </section>
  );
}

function LogosStrip() {
  const items = ['Ubuntu 20.04+', 'Debian 11+', 'CentOS Stream 9', 'Rocky 9', 'Arch'];
  return (
    <section className="bg-zinc-950">
      <div className="max-w-6xl mx-auto px-5 py-8">
        <p className="text-center text-xs uppercase tracking-widest text-zinc-600 mb-5">
          Работает на любом Linux с systemd
        </p>
        <div className="flex flex-wrap items-center justify-center gap-x-10 gap-y-4 opacity-70">
          {items.map((x) => (
            <span key={x} className="text-sm font-medium text-zinc-500">{x}</span>
          ))}
        </div>
      </div>
    </section>
  );
}

function TwoModes() {
  return (
    <section id="modes" className="relative py-24 md:py-32 border-t border-zinc-900/80 overflow-hidden">
      <KanjiWatermark
        char="二"
        className="right-[3%] top-[15%] text-[160px] md:text-[240px] hidden md:block"
        target={0.03}
      />

      <div className="relative max-w-6xl mx-auto px-5">
        <Reveal>
          <div className="text-center max-w-2xl mx-auto">
            <JapaneseDivider kanji="二" label="Two Modes" />
            <h2 className="text-3xl md:text-4xl font-semibold tracking-tight">
              Два режима. Один инструмент.
            </h2>
            <p className="mt-4 text-zinc-400 leading-relaxed">
              SCAN — главный режим, разовый аудит. WATCH — опциональный наблюдатель,
              который продолжает следить после аудита.
            </p>
          </div>
        </Reveal>

        <Reveal delay={0.1}>
          <div className="mt-14 grid grid-cols-1 md:grid-cols-2 gap-5">
            <ModeCard
              icon={ScanSearch}
              kanji="査"
              tag="главный режим"
              title="SCAN"
              subtitle="60-секундный аудит"
              description="Запустил → собрал данные → получил отчёт → закрыл. Не висит в памяти, не жрёт ресурсы."
              bullets={[
                'Security Score 0–100',
                'Red flags с объяснением',
                'Меню harden — выбираешь что применить',
                'AI-разбор простым языком (опционально)',
              ]}
            />
            <ModeCard
              icon={Eye}
              kanji="番"
              tag="опционально"
              title="WATCH"
              subtitle="Постоянный наблюдатель"
              description="Сохраняет baseline → следит за отклонениями → шлёт в Telegram. Раз в 5 минут, ~0.1% CPU."
              bullets={[
                'Поведенческие правила (без сигнатур)',
                'Whitelist (auto + manual)',
                'Telegram-алерты — только односторонние',
                'Откат hardening всегда возможен',
              ]}
            />
          </div>
        </Reveal>
      </div>
    </section>
  );
}

function ModeCard({ icon: Icon, kanji, tag, title, subtitle, description, bullets }) {
  return (
    <div className="relative rounded-2xl border border-zinc-800/80 bg-zinc-900/40 p-6 md:p-7 hover:border-sky-500/30 transition-colors group overflow-hidden">
      <span
        className="absolute right-4 top-3 text-7xl text-zinc-800/60 select-none pointer-events-none"
        style={{ fontFamily: '"Noto Serif JP", serif', fontWeight: 500, lineHeight: 1 }}
        aria-hidden
      >
        {kanji}
      </span>
      <div className="relative">
        <div className="flex items-center gap-3 mb-4">
          <span className="inline-flex items-center justify-center w-11 h-11 rounded-xl border border-sky-500/30 bg-sky-500/10 text-sky-400">
            <Icon size={22} />
          </span>
          <div>
            <div className="text-[10px] uppercase tracking-widest text-zinc-500 font-medium">
              {tag}
            </div>
            <div className="text-2xl font-semibold tracking-tight text-zinc-100">{title}</div>
          </div>
        </div>
        <div className="text-sm font-semibold text-sky-300 mb-2">{subtitle}</div>
        <p className="text-sm text-zinc-400 leading-relaxed mb-5">{description}</p>
        <ul className="space-y-1.5">
          {bullets.map((b) => (
            <li key={b} className="flex items-start gap-2 text-sm text-zinc-300">
              <Check size={15} className="text-sky-400 shrink-0 mt-0.5" strokeWidth={2.4} />
              <span>{b}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function Features() {
  const features = [
    {
      icon: Network,
      title: 'Аудит сети и портов',
      description: 'Слушающие порты, established-соединения, intrazone-сервисы на 0.0.0.0 — всё попадает в отчёт с red flags.',
    },
    {
      icon: Lock,
      title: 'SSH / firewall / sysctl',
      description: 'PermitRootLogin, PasswordAuth, default policy iptables, syncookies, ASLR — стандартные best practices в одном клике.',
    },
    {
      icon: Brain,
      title: 'AI на выбор',
      description: 'Claude, GPT-4o или Gemini — твой ключ, твой счёт. Можно вообще без AI — отчёт читаем и так.',
    },
    {
      icon: Bell,
      title: 'Telegram-алерты',
      description: 'Только односторонняя связь — алерты идут наружу, бот не принимает команды. Безопасно по дизайну.',
    },
    {
      icon: FileWarning,
      title: 'File integrity',
      description: 'Хеши /etc/passwd, /etc/shadow, sudoers, sshd_config, authorized_keys — изменился без обновления пакетов? Алерт.',
    },
    {
      icon: Gauge,
      title: 'Лёгкий по дизайну',
      description: 'Polling через ss/ps/psutil раз в 5 минут. Никакого eBPF, никаких баз. Работает на любом ядре 3.10+.',
    },
  ];

  return (
    <section id="features" className="relative py-24 md:py-32 border-t border-zinc-900/80">
      <div className="max-w-6xl mx-auto px-5">
        <Reveal>
          <div className="max-w-2xl mx-auto text-center">
            <JapaneseDivider kanji="技" label="Capabilities" />
            <h2 className="text-3xl md:text-4xl font-semibold tracking-tight">
              Всё, что нужно для контроля одного сервера
            </h2>
            <p className="mt-4 text-zinc-400 leading-relaxed">
              Yagura — это мини-антивирус для сервера, но без баз сигнатур.
              Не ищет известные вирусы — анализирует поведение и конфигурацию.
            </p>
          </div>
        </Reveal>

        <div className="mt-14 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {features.map((f, i) => (
            <FeatureCard key={f.title} {...f} delay={i * 0.05} />
          ))}
        </div>
      </div>
    </section>
  );
}

function BehavioralRules() {
  const groups = [
    {
      icon: Activity,
      title: 'Сеть и процессы',
      items: [
        'Появился слушающий порт которого не было в baseline',
        'Listener на 0.0.0.0 для процесса из /tmp или /dev/shm',
        'CPU процесса >80% устойчиво >5 мин + сетевые соединения (cryptominer)',
        'bash/sh/python/perl имеет ESTABLISHED исходящее на внешний IP (reverse-shell)',
      ],
    },
    {
      icon: Fingerprint,
      title: 'Файлы и пользователи',
      items: [
        'Изменился хеш /etc/passwd, /etc/shadow, /etc/sudoers, sshd_config, authorized_keys',
        'Появился новый аккаунт с UID 0',
        'В /etc/sudoers или sudoers.d/ добавлен новый юзер',
        'Юзеры с пустым паролем в /etc/shadow',
      ],
    },
    {
      icon: AlertTriangle,
      title: 'Cron и systemd',
      items: [
        'Появился новый cron-job которого не было в baseline',
        'Cron содержит curl/wget с pipe в shell или base64-команды',
        'Появился enabled systemd-юнит которого не было в baseline',
        'Systemd-юнит с ExecStart из /tmp, /dev/shm или /var/tmp',
      ],
    },
    {
      icon: Radar,
      title: 'SSH и трафик',
      items: [
        'Успешный SSH-логин с IP которого не было в whitelist',
        'Brute-force burst: >20 неудачных попыток с одного IP за 5 мин',
        'Исходящий трафик >5x от средней (DDoS-зомби или эксфильтрация)',
        'Резкий рост DNS-запросов (поведение DGA)',
      ],
    },
  ];

  return (
    <section className="relative py-24 md:py-32 border-t border-zinc-900/80 overflow-hidden">
      <KanjiWatermark
        char="罠"
        className="left-[3%] top-[15%] text-[160px] md:text-[240px] hidden md:block"
        target={0.03}
      />

      <div className="relative max-w-6xl mx-auto px-5">
        <Reveal>
          <div className="text-center max-w-2xl mx-auto">
            <JapaneseDivider kanji="罠" label="The Patterns" />
            <h2 className="text-3xl md:text-4xl font-semibold tracking-tight">
              Что Yagura ловит
            </h2>
            <p className="mt-4 text-zinc-400 leading-relaxed">
              Вместо баз сигнатур — поведение. Эти паттерны работают против любого malware,
              известного и неизвестного.
            </p>
          </div>
        </Reveal>

        <Reveal delay={0.1}>
          <div className="mt-12 grid grid-cols-1 md:grid-cols-2 gap-4">
            {groups.map((g, i) => (
              <RuleGroup key={g.title} {...g} delay={i * 0.05} />
            ))}
          </div>
        </Reveal>

        <Reveal delay={0.2}>
          <p className="mt-8 text-center text-xs text-zinc-500 max-w-xl mx-auto leading-relaxed">
            Полный список из 18+ scan-правил и 14+ watch-правил —{' '}
            <a href={REPO_URL} target="_blank" rel="noreferrer" className="text-sky-400 hover:text-sky-300">
              в README на GitLab
            </a>.
          </p>
        </Reveal>
      </div>
    </section>
  );
}

function RuleGroup({ icon: Icon, title, items, delay = 0 }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-60px' }}
      transition={{ duration: 0.5, delay, ease: [0.22, 1, 0.36, 1] }}
      className="rounded-2xl border border-zinc-800/80 bg-zinc-900/40 p-6 hover:border-sky-500/30 transition-colors"
    >
      <div className="flex items-center gap-3 mb-4">
        <span className="inline-flex items-center justify-center w-10 h-10 rounded-lg border border-sky-500/30 bg-sky-500/10 text-sky-400">
          <Icon size={18} />
        </span>
        <h3 className="text-base font-semibold text-zinc-100">{title}</h3>
      </div>
      <ul className="space-y-2">
        {items.map((it) => (
          <li key={it} className="flex items-start gap-2.5 text-sm text-zinc-400 leading-relaxed">
            <span className="mt-1.5 w-1 h-1 rounded-full bg-sky-400/70 shrink-0" />
            <span>{it}</span>
          </li>
        ))}
      </ul>
    </motion.div>
  );
}

function Versus() {
  const cols = [
    { name: 'Yagura', accent: true },
    { name: 'ClamAV', accent: false },
    { name: 'Wazuh', accent: false },
    { name: 'CrowdStrike', accent: false },
  ];

  const rows = [
    { label: 'Установка',     vals: ['curl | bash',          'apt + cron',          'агент + сервер',     'enterprise sales'] },
    { label: 'Размер',        vals: ['~30 МБ venv',          '~500 МБ базы',        '~1 ГБ + сервер',     'агент + cloud'] },
    { label: 'Подход',        vals: ['поведение',            'сигнатуры',           'SIEM',               'ML + сигнатуры'] },
    { label: 'База вирусов',  vals: ['не нужна',             'обязательно',         'через Suricata',     'проприетарная'] },
    { label: 'Нагрузка CPU',  vals: ['~0.1%',                '~5% при скане',       '~3% постоянно',      'varies'] },
    { label: 'Цена',          vals: ['$0',                   '$0',                  '$0',                 '$$$$'] },
    { label: 'TG алерты',     vals: ['да, из коробки',       'нет',                 'через интеграции',   'через интеграции'] },
    { label: 'Для VPS',       vals: ['идеально',             'избыточно',           'избыточно',          'overkill'] },
  ];

  return (
    <section className="relative py-24 md:py-32 border-t border-zinc-900/80 overflow-hidden">
      <KanjiWatermark
        char="比"
        className="left-[3%] top-[15%] text-[160px] md:text-[240px] hidden md:block"
        target={0.03}
      />

      <div className="relative max-w-5xl mx-auto px-5">
        <Reveal>
          <div className="text-center max-w-2xl mx-auto">
            <JapaneseDivider kanji="比" label="The Comparison" />
            <h2 className="text-3xl md:text-4xl font-semibold tracking-tight">
              Yagura vs остальные
            </h2>
            <p className="mt-4 text-zinc-400 leading-relaxed">
              Не замена ClamAV или Wazuh — другой класс инструмента.
              Сделан для тех у кого <span className="text-zinc-200">1–3 сервера и нет SOC</span>.
            </p>
          </div>
        </Reveal>

        <Reveal delay={0.1}>
          <div className="mt-12 overflow-x-auto rounded-2xl border border-zinc-900/80">
            <table className="w-full min-w-[640px] border-collapse text-sm">
              <thead>
                <tr className="bg-zinc-950">
                  <th className="text-left px-5 py-4 text-xs uppercase tracking-wider text-zinc-500 font-medium border-b border-zinc-900/80">Что</th>
                  {cols.map((c) => (
                    <th
                      key={c.name}
                      className={`text-left px-5 py-4 text-sm font-semibold border-b border-zinc-900/80 ${
                        c.accent ? 'text-sky-400' : 'text-zinc-300'
                      }`}
                    >
                      {c.name}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.label} className="bg-zinc-950 border-t border-zinc-900/80">
                    <td className="px-5 py-3 text-xs uppercase tracking-wider text-zinc-500 font-medium align-top">
                      {r.label}
                    </td>
                    {r.vals.map((v, i) => (
                      <td
                        key={i}
                        className={`px-5 py-3 leading-relaxed ${
                          i === 0 ? 'text-zinc-100' : 'text-zinc-400'
                        }`}
                      >
                        {v}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Reveal>

        <Reveal delay={0.2}>
          <p className="mt-8 text-center text-sm text-zinc-500 max-w-2xl mx-auto leading-relaxed">
            Wazuh и CrowdStrike — это SOC-инструменты для команд с выделенными аналитиками.
            Yagura — для одного фрилансера с одним VPS, который не хочет проснуться к defaced сайту.
          </p>
        </Reveal>
      </div>
    </section>
  );
}

function HowItWorks() {
  const steps = [
    {
      num: '01',
      title: 'Запусти install.sh',
      description: 'Одна команда от root. Скрипт поставит Python, скачает Yagura, запустит wizard.',
    },
    {
      num: '02',
      title: 'Ответь на вопросы',
      description: 'AI-провайдер (опционально), какие harden-действия применить, нужен ли watch + Telegram.',
    },
    {
      num: '03',
      title: 'Получай отчёт и алерты',
      description: 'Markdown-отчёт сохраняется. Если включил watch — раз в 5 минут проверка + Telegram при аномалии.',
    },
  ];

  return (
    <section id="how" className="relative py-24 md:py-32 border-t border-zinc-900/80">
      <div className="max-w-6xl mx-auto px-5">
        <Reveal>
          <div className="text-center max-w-2xl mx-auto">
            <JapaneseDivider kanji="歩" label="The Path" />
            <h2 className="text-3xl md:text-4xl font-semibold tracking-tight">
              Три шага до защищённого сервера
            </h2>
          </div>
        </Reveal>

        <div className="mt-14 grid grid-cols-1 md:grid-cols-3 gap-5 md:gap-8 relative">
          <div className="hidden md:block absolute top-9 left-[16%] right-[16%] h-px bg-gradient-to-r from-transparent via-zinc-800 to-transparent" />
          {steps.map((s, i) => (
            <Reveal key={s.num} delay={i * 0.08}>
              <div className="relative">
                <div className="w-[72px] h-[72px] rounded-2xl border border-zinc-800 bg-zinc-900/60 backdrop-blur flex items-center justify-center mb-5 mx-auto">
                  <span className="text-2xl font-mono font-semibold text-zinc-300 tracking-tight">
                    {s.num}
                  </span>
                </div>
                <h3 className="text-lg font-semibold text-center text-zinc-100 mb-2">{s.title}</h3>
                <p className="text-sm text-zinc-400 leading-relaxed text-center max-w-xs mx-auto">
                  {s.description}
                </p>
              </div>
            </Reveal>
          ))}
        </div>

        <Reveal delay={0.2}>
          <div id="install" className="mt-14 max-w-2xl mx-auto">
            <InstallCommand />
            <p className="mt-3 text-center text-xs text-zinc-500">
              Затем: <code className="text-zinc-400">yagura scan | harden | watch start | watch status | uninstall</code>
            </p>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

function DemoSection() {
  return (
    <section className="relative py-24 md:py-32 border-t border-zinc-900/80 overflow-hidden">
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[400px] bg-sky-500/5 blur-[120px] rounded-full" />
      </div>
      <KanjiWatermark
        char="眼"
        className="right-[2%] top-[10%] text-[160px] md:text-[240px] hidden md:block"
        target={0.03}
      />

      <div className="relative max-w-3xl mx-auto px-5 text-center">
        <Reveal>
          <JapaneseDivider kanji="眼" label="The Eye" />
          <h2 className="text-3xl md:text-4xl font-semibold tracking-tight leading-tight">
            Что приходит в Telegram
          </h2>
          <p className="mt-4 text-zinc-400 leading-relaxed">
            Какое правило сработало, на каком процессе, с какого IP, в какое время —
            и что делать прямо сейчас. Если подключён AI — добавляется три строки разбора:
            серьёзно ли это, что выполнить сейчас, как предотвратить в будущем.
          </p>
          <p className="mt-3 text-zinc-500 leading-relaxed text-sm">
            Связь односторонняя — сервер шлёт в TG, бот не принимает команды. Это не вектор атаки.
          </p>
        </Reveal>

        <Reveal delay={0.15}>
          <div className="mt-10 max-w-2xl mx-auto rounded-2xl border border-zinc-800/80 bg-zinc-900/60 backdrop-blur p-5 md:p-6 text-left font-mono text-xs md:text-sm leading-relaxed">
            <div className="text-amber-400">🚨 YAGURA ALERT — myserver.example.com</div>
            <div className="text-zinc-400">Severity: HIGH</div>
            <div className="text-zinc-400 mb-3">Rule: W-NET-001 (New listener)</div>
            <div className="text-zinc-200">Появился слушающий порт 4444/tcp</div>
            <div className="text-zinc-400">Процесс: /tmp/.x/miner (PID 13371)</div>
            <div className="text-zinc-400">Запустил: root</div>
            <div className="text-zinc-400 mb-3">Cmdline: ./miner --pool xmr.pool.net:4444</div>
            <div className="text-sky-400">Что делать:</div>
            <div className="text-zinc-300">— ps -fp 13371</div>
            <div className="text-zinc-300">— kill -9 13371 && rm -rf /tmp/.x</div>
            <div className="text-zinc-300">— crontab -l && cat /etc/crontab</div>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

function FAQ() {
  const items = [
    {
      q: 'Это правда полностью open-source? Никакого SaaS?',
      a: 'Да. Один Python-инструмент, MIT-лицензия. Нет бэкенда, нет аккаунтов, нет телеметрии. Все ключи (AI provider, Telegram bot) — твои собственные, лежат на твоём сервере в /etc/yagura/config.yml (mode 0600).',
    },
    {
      q: 'Чем отличается от ClamAV или Wazuh?',
      a: 'ClamAV — антивирус по сигнатурам, ловит только то что уже в базе. Wazuh — full-stack SIEM на сервер + агенты, нужно команда чтобы это администрировать. Yagura — поведенческий аудит + watchdog для одного сервера, ставится одной командой, не требует баз и серверов.',
    },
    {
      q: 'А fail2ban не делает то же самое?',
      a: 'Нет. fail2ban — реактивная защита от брутфорса публичных сервисов. Yagura — проактивный аудит конфигурации (PermitRootLogin, ASLR, sudoers, hashes) + поведенческий watchdog (новые listener, reverse-shell heuristic, file integrity). Это разные слои, хорошо стоят вместе.',
    },
    {
      q: 'Какой AI выбрать?',
      a: 'Любой из трёх: Anthropic Claude, OpenAI GPT-4o, Google Gemini. Wizard спросит при установке. Можно вообще без AI — отчёт и так читаем, без AI watchdog тоже работает.',
    },
    {
      q: 'Сколько стоит AI?',
      a: 'Один scan-запрос — примерно $0.001–0.01 в зависимости от провайдера. AI вызывается только: 1) при ручном scan, 2) при HIGH/CRITICAL алертах в watch (для LOW/MEDIUM не тратим кредиты). За месяц watch на спокойном VPS — обычно меньше доллара.',
    },
    {
      q: 'Безопасно ли запускать curl | sudo bash?',
      a: 'Скрипт короткий, читай его перед запуском: gitlab.com/<user>/yagura/-/blob/main/install.sh. Он только определяет дистрибутив, ставит Python если нет, скачивает Yagura и запускает интерактивный wizard. Никаких внешних серверов кроме gitlab.com.',
    },
    {
      q: 'Что watchdog делает с CPU?',
      a: 'Polling раз в 5 минут через ss/ps/psutil — около 0.1% CPU и 22 МБ RAM в простое. Никакого eBPF, никаких ядерных модулей, никаких inotify-демонов в фоне. Если 5 мин мало — настраивается в config.yml.',
    },
    {
      q: 'А если harden что-то сломает?',
      a: 'Каждое harden-действие сохраняет rollback-команду в /etc/yagura/config.yml (harden_history). Откат — `yagura harden rollback <action-id>`. Полное удаление — `yagura uninstall` — откатит ВСЁ что Yagura применил, и удалит сам себя.',
    },
    {
      q: 'Почему Telegram односторонний? Удобно же командой реагировать.',
      a: 'Двусторонний бот = новый вектор атаки. Если кто-то получит токен — сможет управлять сервером. Yagura по дизайну — наблюдатель, не агент: алерты идут наружу, реакция — твоя ручная или через goronin/fail2ban. Это сознательное ограничение, а не временное.',
    },
    {
      q: 'Можно ли поставить на несколько серверов?',
      a: 'Да. Каждый сервер — независимый Yagura со своим конфигом и своим baseline. Можно слать алерты в один общий Telegram chat — в сообщении указано имя хоста.',
    },
  ];

  return (
    <section id="faq" className="py-24 md:py-32 border-t border-zinc-900/80">
      <div className="max-w-3xl mx-auto px-5">
        <Reveal>
          <div className="text-center">
            <JapaneseDivider kanji="問" label="Questions" />
            <h2 className="text-3xl md:text-4xl font-semibold tracking-tight">
              Ответы на самое важное
            </h2>
          </div>
        </Reveal>

        <Reveal delay={0.1}>
          <div className="mt-10">
            {items.map((it) => (
              <FAQItem key={it.q} question={it.q} answer={it.a} />
            ))}
          </div>
        </Reveal>
      </div>
    </section>
  );
}

const DONORS = [
  // { handle: '@example', note: 'first supporter' },
];

const TELEGRAM_HANDLE = '@kitay9';
const TELEGRAM_URL = 'https://t.me/kitay9';

function Support() {
  const wallets = [
    {
      label: 'USDT',
      network: 'TRON · TRC20',
      address: 'TF9F2FPkreHVfbe8tZtn4V76j3jLo4SeXM',
    },
    {
      label: 'TON',
      network: 'The Open Network',
      address: 'UQBl88kXWJWyHkDPkWNYQwwSCiCAIfA2DiExtZElwJFlIc1o',
    },
  ];

  return (
    <section id="support" className="relative py-24 md:py-32 border-t border-zinc-900/80 overflow-hidden">
      <KanjiWatermark
        char="恩"
        className="left-[5%] top-[20%] text-[160px] md:text-[240px] hidden md:block"
        target={0.03}
      />

      <div className="relative max-w-3xl mx-auto px-5">
        <Reveal>
          <div className="text-center">
            <JapaneseDivider kanji="恩" label="Gratitude" />
            <h2 className="text-3xl md:text-4xl font-semibold tracking-tight">
              Поддержать проект
            </h2>
            <p className="mt-4 text-zinc-400 leading-relaxed max-w-xl mx-auto">
              Yagura развивается на энтузиазме и в свободное время. Если оказался полезен — поддержать можно криптой.
              Любая сумма помогает выделить больше времени на новые правила и фичи из roadmap.
            </p>
          </div>
        </Reveal>

        <Reveal delay={0.1}>
          <div className="mt-10 grid grid-cols-1 md:grid-cols-2 gap-4">
            {wallets.map((w, i) => (
              <WalletCard key={w.label} {...w} delay={i * 0.05} />
            ))}
          </div>
        </Reveal>

        <Reveal delay={0.15}>
          <div className="mt-10 rounded-2xl border border-sky-500/20 bg-gradient-to-br from-sky-500/5 via-zinc-900/40 to-zinc-900/40 p-6 md:p-8">
            <div className="flex items-start gap-4">
              <div className="shrink-0 inline-flex items-center justify-center w-11 h-11 rounded-xl border border-sky-500/30 bg-sky-500/10 text-sky-400">
                <Send size={18} />
              </div>
              <div className="flex-1 min-w-0">
                <h3 className="text-base md:text-lg font-semibold text-zinc-100">
                  Хочешь попасть в стену чести?
                </h3>
                <p className="mt-1.5 text-sm text-zinc-400 leading-relaxed">
                  После доната напиши в Telegram{' '}
                  <a
                    href={TELEGRAM_URL}
                    target="_blank"
                    rel="noreferrer"
                    className="text-sky-400 hover:text-sky-300 font-mono"
                  >
                    {TELEGRAM_HANDLE}
                  </a>{' '}
                  свой ник — добавлю в список ниже навсегда.
                </p>
                <a
                  href={TELEGRAM_URL}
                  target="_blank"
                  rel="noreferrer"
                  className="mt-4 inline-flex items-center gap-1.5 text-xs font-medium px-3 py-2 rounded-md border border-sky-500/30 hover:border-sky-500/60 hover:bg-sky-500/10 transition-colors text-sky-300"
                >
                  <Send size={13} />
                  Написать в Telegram
                </a>
              </div>
            </div>
          </div>
        </Reveal>

        <Reveal delay={0.2}>
          <DonorsWall donors={DONORS} />
        </Reveal>
      </div>
    </section>
  );
}

function DonorsWall({ donors }) {
  const empty = !donors || donors.length === 0;

  return (
    <div className="mt-10">
      <div className="flex items-center gap-3 mb-5">
        <Heart size={14} className="text-sky-400" strokeWidth={2.4} />
        <h3 className="text-sm font-semibold tracking-wide uppercase text-zinc-300">
          Стена чести
        </h3>
        {!empty && (
          <span className="text-xs text-zinc-500 font-mono ml-auto">
            {donors.length} {donors.length === 1 ? 'самурай' : 'самураев'}
          </span>
        )}
      </div>

      {empty ? (
        <div className="rounded-xl border border-dashed border-zinc-800 bg-zinc-900/30 p-8 text-center">
          <p className="text-sm text-zinc-500">
            Пока пусто.{' '}
            <a
              href={TELEGRAM_URL}
              target="_blank"
              rel="noreferrer"
              className="text-sky-400 hover:text-sky-300 font-medium"
            >
              Будь первым
            </a>{' '}
            — твой ник окажется здесь и останется навсегда.
          </p>
        </div>
      ) : (
        <ul className="flex flex-wrap gap-2">
          {donors.map((d) => {
            const handle = d.handle.startsWith('@') ? d.handle : `@${d.handle}`;
            const tgUrl = `https://t.me/${handle.replace(/^@/, '')}`;
            return (
              <li key={handle}>
                <a
                  href={tgUrl}
                  target="_blank"
                  rel="noreferrer"
                  title={d.note || handle}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full border border-zinc-800 bg-zinc-900/50 hover:border-sky-500/40 hover:bg-sky-500/5 transition-colors text-sm text-zinc-300 hover:text-zinc-100 font-mono"
                >
                  <Heart size={11} className="text-sky-400/70" fill="currentColor" />
                  {handle}
                </a>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

function WalletCard({ label, network, address }) {
  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(address);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* empty */
    }
  };

  return (
    <div className="rounded-2xl border border-zinc-800 bg-zinc-900/40 p-5 backdrop-blur">
      <div className="flex items-baseline justify-between mb-3">
        <span className="text-base font-semibold text-zinc-100">{label}</span>
        <span className="text-xs text-zinc-500 font-mono">{network}</span>
      </div>
      <div className="flex items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-950/60 p-3">
        <code className="text-xs text-sky-300 font-mono break-all flex-1 min-w-0">
          {address}
        </code>
        <button
          onClick={onCopy}
          className="shrink-0 inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1.5 rounded-md border border-zinc-700 hover:border-sky-500/50 hover:bg-sky-500/10 transition-colors text-zinc-300"
          aria-label={`Скопировать адрес ${label}`}
        >
          {copied ? <Check size={14} className="text-sky-400" /> : <Copy size={14} />}
          {copied ? 'Скопировано' : 'Копировать'}
        </button>
      </div>
    </div>
  );
}

function CTA() {
  return (
    <section className="relative py-24 md:py-32 border-t border-zinc-900/80 overflow-hidden">
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[400px] bg-sky-500/10 blur-[120px] rounded-full" />
      </div>
      <div className="relative max-w-3xl mx-auto px-5 text-center">
        <Reveal>
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-xl border border-sky-500/30 bg-sky-500/10 text-sky-400 mb-6">
            <Shield size={26} />
          </div>
          <h2 className="text-3xl md:text-5xl font-semibold tracking-tight leading-tight">
            Поставь башню.<br />
            <span className="bg-gradient-to-r from-sky-400 to-cyan-300 bg-clip-text text-transparent">
              Узнай, что не так с твоим сервером.
            </span>
          </h2>
          <p className="mt-5 text-zinc-400 max-w-xl mx-auto">
            60 секунд от curl до отчёта со Security Score и red flags.
          </p>

          <div className="mt-8 max-w-2xl mx-auto">
            <InstallCommand />
          </div>

          <div className="mt-5 flex items-center justify-center">
            <a
              href={REPO_URL}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-2 text-zinc-300 hover:text-zinc-100 border border-zinc-800 hover:border-zinc-700 rounded-xl px-5 py-3 transition-colors"
            >
              <Github size={16} />
              Посмотреть код на GitLab
            </a>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

function Footer() {
  return (
    <footer className="border-t border-zinc-900/80 py-10">
      <div className="max-w-6xl mx-auto px-5 flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-2 text-sm text-zinc-500">
          <span>YAGURA · MIT · © {new Date().getFullYear()}</span>
          <span className="text-zinc-700">·</span>
          <a
            href="https://gitlab.com/kitay-sudo"
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1 text-zinc-500 hover:text-sky-400 transition-colors"
          >
            by <Github size={12} /> kitay-sudo
          </a>
        </div>
        <div className="flex items-center gap-5 text-sm text-zinc-500">
          <a href="#modes" className="hover:text-zinc-300 transition-colors">Режимы</a>
          <a href="#features" className="hover:text-zinc-300 transition-colors">Возможности</a>
          <a href="#install" className="hover:text-zinc-300 transition-colors">Установка</a>
          <a href="#faq" className="hover:text-zinc-300 transition-colors">FAQ</a>
          <a href="#support" className="hover:text-zinc-300 transition-colors">Поддержать</a>
          <a href={REPO_URL} target="_blank" rel="noreferrer" className="hover:text-zinc-300 transition-colors flex items-center gap-1.5">
            <Github size={14} /> GitLab
          </a>
        </div>
      </div>
    </footer>
  );
}
