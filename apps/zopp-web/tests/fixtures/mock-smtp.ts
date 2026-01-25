/**
 * Mock SMTP server for capturing verification emails in E2E tests.
 *
 * Uses smtp-server to create a real SMTP server that captures emails,
 * allowing tests to retrieve verification codes from the email body.
 *
 * This is a TypeScript equivalent of the Rust mock SMTP in e2e-tests.
 * We need a separate implementation because Playwright tests run in Node.js.
 */

import { SMTPServer, SMTPServerAddress, SMTPServerSession, SMTPServerDataStream } from 'smtp-server';
import { simpleParser, ParsedMail } from 'mailparser';
import * as net from 'net';

export interface CapturedEmail {
  from: string;
  to: string[];
  subject: string;
  text: string;
  html: string | false;
}

export class MockSmtpServer {
  private server: SMTPServer;
  private emails: CapturedEmail[] = [];
  private port: number = 0;
  private _isRunning: boolean = false;

  constructor() {
    this.server = new SMTPServer({
      authOptional: true,
      disabledCommands: ['STARTTLS', 'AUTH'],
      onData: (stream: SMTPServerDataStream, session: SMTPServerSession, callback: (err?: Error | null) => void) => {
        this.handleData(stream, session).then(() => callback()).catch(callback);
      },
      onMailFrom: (address: SMTPServerAddress, session: SMTPServerSession, callback: (err?: Error | null) => void) => {
        callback();
      },
      onRcptTo: (address: SMTPServerAddress, session: SMTPServerSession, callback: (err?: Error | null) => void) => {
        callback();
      },
    });
  }

  private async handleData(stream: SMTPServerDataStream, session: SMTPServerSession): Promise<void> {
    const parsed: ParsedMail = await simpleParser(stream);

    const email: CapturedEmail = {
      from: session.envelope.mailFrom ? (session.envelope.mailFrom as SMTPServerAddress).address : '',
      to: session.envelope.rcptTo.map((r: SMTPServerAddress) => r.address),
      subject: parsed.subject || '',
      text: parsed.text || '',
      html: parsed.html || false,
    };

    this.emails.push(email);
  }

  private async findAvailablePort(): Promise<number> {
    return new Promise((resolve, reject) => {
      const server = net.createServer();
      server.listen(0, '127.0.0.1', () => {
        const address = server.address();
        if (address && typeof address === 'object') {
          const port = address.port;
          server.close(() => resolve(port));
        } else {
          reject(new Error('Failed to get port'));
        }
      });
      server.on('error', reject);
    });
  }

  async start(): Promise<number> {
    this.port = await this.findAvailablePort();

    return new Promise((resolve, reject) => {
      this.server.listen(this.port, '127.0.0.1', () => {
        this._isRunning = true;
        resolve(this.port);
      });
      this.server.on('error', reject);
    });
  }

  async stop(): Promise<void> {
    return new Promise((resolve) => {
      this._isRunning = false;
      this.server.close(() => resolve());
    });
  }

  getPort(): number {
    return this.port;
  }

  isRunning(): boolean {
    return this._isRunning;
  }

  getEmails(): CapturedEmail[] {
    return [...this.emails];
  }

  getEmailFor(toEmail: string): CapturedEmail | undefined {
    return [...this.emails].reverse().find(e =>
      e.to.some(t => t.toLowerCase().includes(toEmail.toLowerCase()))
    );
  }

  /**
   * Extract verification code from the latest email to an address.
   * Looks for a 6-digit code in the email body.
   */
  getVerificationCode(toEmail: string): string | null {
    const email = this.getEmailFor(toEmail);
    if (!email) return null;

    const match = email.text.match(/\b(\d{6})\b/);
    return match ? match[1] : null;
  }

  clear(): void {
    this.emails = [];
  }

  async waitForEmail(timeoutMs: number = 5000): Promise<boolean> {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      if (this.emails.length > 0) {
        return true;
      }
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    return false;
  }

  async waitForEmailTo(toEmail: string, timeoutMs: number = 5000): Promise<boolean> {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      if (this.getEmailFor(toEmail)) {
        return true;
      }
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    return false;
  }
}
