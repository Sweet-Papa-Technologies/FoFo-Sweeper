import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { renderHtmlReport, type HtmlReportInput } from './html-report.js';
import { renderMarkdownReport } from './report.js';

export type ReportFormat = 'both' | 'html' | 'md';

export interface WriteReportsResult {
  mdPath?: string;
  htmlPath?: string;
}

export function writeSessionReports(
  sessionDir: string,
  input: HtmlReportInput,
  format: ReportFormat = 'both'
): WriteReportsResult {
  const result: WriteReportsResult = {};
  if (format === 'both' || format === 'md') {
    const md = renderMarkdownReport(input);
    const mdPath = path.join(sessionDir, 'report.md');
    fs.writeFileSync(mdPath, md, 'utf8');
    result.mdPath = mdPath;
  }
  if (format === 'both' || format === 'html') {
    const html = renderHtmlReport(input);
    const htmlPath = path.join(sessionDir, 'report.html');
    fs.writeFileSync(htmlPath, html, 'utf8');
    result.htmlPath = htmlPath;
  }
  return result;
}

export function openReportInBrowser(filePath: string): boolean {
  try {
    if (process.platform === 'win32') {
      const child = spawn('cmd.exe', ['/c', 'start', '', filePath], {
        detached: true,
        stdio: 'ignore',
        windowsHide: true,
      });
      child.unref();
      return true;
    }
    if (process.platform === 'darwin') {
      const child = spawn('open', [filePath], { detached: true, stdio: 'ignore' });
      child.unref();
      return true;
    }
    const child = spawn('xdg-open', [filePath], { detached: true, stdio: 'ignore' });
    child.unref();
    return true;
  } catch {
    return false;
  }
}
