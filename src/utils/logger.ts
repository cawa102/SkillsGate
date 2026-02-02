import chalk from 'chalk'

/**
 * Log levels
 */
export type LogLevel = 'debug' | 'info' | 'warn' | 'error'

/**
 * Logger configuration
 */
interface LoggerConfig {
  level: LogLevel
  quiet: boolean
}

const LOG_LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3
}

let config: LoggerConfig = {
  level: 'info',
  quiet: false
}

/**
 * Configure the logger
 */
export function configureLogger(options: Partial<LoggerConfig>): void {
  config = { ...config, ...options }
}

/**
 * Check if a log level should be displayed
 */
function shouldLog(level: LogLevel): boolean {
  if (config.quiet && level !== 'error') {
    return false
  }
  return LOG_LEVELS[level] >= LOG_LEVELS[config.level]
}

/**
 * Format a log message with timestamp
 */
function formatMessage(level: LogLevel, message: string): string {
  const timestamp = new Date().toISOString()
  const prefix = `[${timestamp}] [${level.toUpperCase()}]`
  return `${prefix} ${message}`
}

/**
 * Log a debug message
 */
export function debug(message: string, ...args: unknown[]): void {
  if (shouldLog('debug')) {
    console.debug(chalk.gray(formatMessage('debug', message)), ...args)
  }
}

/**
 * Log an info message
 */
export function info(message: string, ...args: unknown[]): void {
  if (shouldLog('info')) {
    console.info(chalk.blue(formatMessage('info', message)), ...args)
  }
}

/**
 * Log a warning message
 */
export function warn(message: string, ...args: unknown[]): void {
  if (shouldLog('warn')) {
    console.warn(chalk.yellow(formatMessage('warn', message)), ...args)
  }
}

/**
 * Log an error message
 */
export function error(message: string, ...args: unknown[]): void {
  if (shouldLog('error')) {
    console.error(chalk.red(formatMessage('error', message)), ...args)
  }
}

/**
 * Log a success message (always shown unless quiet)
 */
export function success(message: string): void {
  if (!config.quiet) {
    console.log(chalk.green(message))
  }
}

/**
 * Log a finding based on severity
 */
export function finding(severity: string, message: string, location: string): void {
  if (config.quiet) {
    return
  }

  const colors: Record<string, (s: string) => string> = {
    critical: chalk.bgRed.white,
    high: chalk.red,
    medium: chalk.yellow,
    low: chalk.cyan,
    info: chalk.gray
  }

  const colorFn = colors[severity] || chalk.white
  const severityLabel = colorFn(`[${severity.toUpperCase()}]`)
  console.log(`${severityLabel} ${message} (${chalk.dim(location)})`)
}

/**
 * Logger interface for named loggers
 */
export interface Logger {
  debug: (message: string, ...args: unknown[]) => void
  info: (message: string, ...args: unknown[]) => void
  warn: (message: string, ...args: unknown[]) => void
  error: (message: string, ...args: unknown[]) => void
}

/**
 * Create a named logger instance
 */
export function createLogger(name: string): Logger {
  const prefix = (msg: string) => `[${name}] ${msg}`

  return {
    debug: (message: string, ...args: unknown[]) => debug(prefix(message), ...args),
    info: (message: string, ...args: unknown[]) => info(prefix(message), ...args),
    warn: (message: string, ...args: unknown[]) => warn(prefix(message), ...args),
    error: (message: string, ...args: unknown[]) => error(prefix(message), ...args)
  }
}

/**
 * Create a spinner-like progress indicator
 */
export function progress(message: string): { stop: (finalMessage?: string) => void } {
  if (config.quiet) {
    return { stop: () => {} }
  }

  const frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
  let i = 0
  const interval = setInterval(() => {
    process.stdout.write(`\r${chalk.cyan(frames[i])} ${message}`)
    i = (i + 1) % frames.length
  }, 80)

  return {
    stop: (finalMessage?: string) => {
      clearInterval(interval)
      process.stdout.write('\r' + ' '.repeat(message.length + 5) + '\r')
      if (finalMessage) {
        console.log(finalMessage)
      }
    }
  }
}
